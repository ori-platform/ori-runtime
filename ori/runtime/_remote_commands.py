# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Authenticated remote commands: ingress, lockout, execution and audit."""

import asyncio
import logging
from typing import Any

from ori.config import Config
from ori.network.events import SensorReading
from ori.network.sms_webhook import SMSWebhookServer
from ori.policy.remote_fetch import (
    RemotePolicyFetchError,
    fetch_remote_device_policy_bundle_by_reference,
)
from ori.runtime._alerts import AlertDelivery
from ori.runtime._device_policy import DevicePolicyRefresh
from ori.runtime._remote_command_wiring import validate_remote_policy_reference_args
from ori.security.remote_commands.commands import RemoteCommand
from ori.security.remote_commands.lockout import (
    evaluate_remote_command_lockout,
    remote_command_sender_key,
)
from ori.security.remote_commands.policy import (
    STATUS_AUDIT_ONLY,
    STATUS_DRY_RUN,
    STATUS_EXECUTED,
    STATUS_FAILED,
    STATUS_PRECONDITION_FAILED,
    STATUS_UNSUPPORTED,
    RemoteCommandExecutionResult,
    classify_remote_command,
    command_requests_dry_run,
    command_result,
)
from ori.security.remote_commands.throttle import RemoteCommandThrottleDecision
from ori.security.threshold_guard import (
    all_trigger_condition_refs,
    check_tier_d_condition_suppression,
    check_tier_d_startup_sensitivity,
    tier_d_config_keys,
)
from ori.security.webhook_signatures import (
    WebhookSignatureConfig,
    WebhookSignatureVerifier,
)
from ori.utils.bool_utils import is_truthy
from ori.utils.time_utils import now_ms

logger = logging.getLogger("ori.runtime")


class RemoteCommands(DevicePolicyRefresh, AlertDelivery):
    """Receiving, gating, executing and auditing remote commands."""

    async def ingest_sms_webhook(self, payload: dict[str, Any]) -> bool:
        """Store one inbound SMS webhook payload for approval workflows."""
        if self._sms_action is None:
            logger.warning("[runtime] SMSAction is not initialised")
            return False
        return await self._sms_action.ingest_incoming_webhook(payload)

    async def _handle_remote_command(
        self, command: RemoteCommand
    ) -> RemoteCommandExecutionResult:
        """Apply runtime-owned execution policy for an authenticated command."""
        try:
            lockout_result = await self._remote_command_lockout_precheck(command)
            if lockout_result is not None:
                result = lockout_result
            else:
                result = await self._execute_remote_command(command)
        except Exception:
            logger.exception(
                "[runtime] remote command execution failed unexpectedly command_id=%s command=%s",
                command.command_id,
                command.command,
            )
            result = command_result(
                command,
                status=STATUS_FAILED,
                detail="unexpected execution error",
                executed=False,
            )

        await self._log_remote_command_execution_result(result)
        return result

    async def _remote_command_lockout_precheck(
        self, command: RemoteCommand
    ) -> RemoteCommandExecutionResult | None:
        """Return a blocking result when sender lockout enforcement applies."""
        cfg = self._remote_command_lockout_config
        enforcement_enabled = is_truthy(cfg.get("enforcement_enabled", False))
        try:
            lockout_state = await self._evaluate_lockout_for_sender(
                channel=command.channel,
                from_number=command.from_number,
            )
        except Exception:
            logger.exception(
                "[runtime] remote command lockout evaluation failed command_id=%s channel=%s sender=%r",
                command.command_id,
                command.channel,
                command.from_number,
            )
            if enforcement_enabled:
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail="remote command lockout evaluation unavailable",
                    executed=False,
                )
            return None

        self._remote_command_lockout_states[
            remote_command_sender_key(
                channel=command.channel,
                from_number=command.from_number,
            )
        ] = lockout_state.as_dict()
        if lockout_state.locked_out:
            logger.warning(
                "[runtime] remote command blocked by lockout command_id=%s channel=%s sender=%r reason=%s",
                command.command_id,
                command.channel,
                command.from_number,
                lockout_state.reason,
            )
            return command_result(
                command,
                status=STATUS_PRECONDITION_FAILED,
                detail=f"remote command sender locked out: {lockout_state.reason}",
                executed=False,
            )
        return None

    async def _execute_remote_command(
        self, command: RemoteCommand
    ) -> RemoteCommandExecutionResult:
        policy_status = classify_remote_command(command)
        if policy_status == STATUS_AUDIT_ONLY:
            return command_result(
                command,
                status=STATUS_AUDIT_ONLY,
                detail="authenticated command accepted but handler is not enabled",
                executed=False,
            )
        if policy_status == STATUS_UNSUPPORTED:
            return command_result(
                command,
                status=STATUS_UNSUPPORTED,
                detail="authenticated command is not supported by this runtime",
                executed=False,
            )

        if command.command == "REFRESH_POLICY":
            if self._config is None or self._dispatcher is None:
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail="runtime config or dispatcher is unavailable",
                    executed=False,
                )
            policy_cfg = (
                self._config.device_policy
                if isinstance(self._config.device_policy, dict)
                else {}
            )
            if not bool(policy_cfg.get("enabled", False)):
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail="device_policy is not enabled",
                    executed=False,
                )

            if command_requests_dry_run(command):
                return command_result(
                    command,
                    status=STATUS_DRY_RUN,
                    detail="would refresh remote DevicePolicy using the existing verified fetch path",
                    executed=False,
                )

            refreshed = await self._refresh_remote_device_policy_once(
                config=self._config,
                dispatcher=self._dispatcher,
                suppress_transient_audit=False,
            )
            if refreshed:
                return command_result(
                    command,
                    status=STATUS_EXECUTED,
                    detail="remote DevicePolicy refresh completed",
                    executed=True,
                )
            return command_result(
                command,
                status=STATUS_FAILED,
                detail="remote DevicePolicy refresh failed or was rejected",
                executed=False,
            )

        if command.command == "APPLY_POLICY":
            if self._config is None or self._dispatcher is None:
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail="runtime config or dispatcher is unavailable",
                    executed=False,
                )
            policy_cfg = (
                self._config.device_policy
                if isinstance(self._config.device_policy, dict)
                else {}
            )
            if not bool(policy_cfg.get("enabled", False)):
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail="device_policy is not enabled",
                    executed=False,
                )

            reference_url = str(command.args.get("url", "") or "").strip()
            expected_sha256 = str(command.args.get("sha256") or "").strip()
            if not reference_url or not expected_sha256:
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail="APPLY_POLICY requires args.url and args.sha256",
                    executed=False,
                )
            reference_error = validate_remote_policy_reference_args(
                reference_url,
                expected_sha256,
            )
            if reference_error is not None:
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail=reference_error,
                    executed=False,
                )

            if command_requests_dry_run(command):
                return command_result(
                    command,
                    status=STATUS_DRY_RUN,
                    detail="would fetch, hash-check, signature-verify, and apply referenced DevicePolicy",
                    executed=False,
                )

            try:
                fetched = await fetch_remote_device_policy_bundle_by_reference(
                    policy_cfg,
                    url=reference_url,
                    expected_sha256=expected_sha256,
                    current_policy_version=self._dispatcher.current_policy_version(),
                )
                await self._apply_fetched_remote_device_policy(
                    config=self._config,
                    fetched=fetched,
                    dispatcher=self._dispatcher,
                )
                return command_result(
                    command,
                    status=STATUS_EXECUTED,
                    detail="referenced DevicePolicy applied",
                    executed=True,
                )
            except RemotePolicyFetchError as exc:
                await self._audit_policy_rejection(
                    device_id=self._config.device.id,
                    reason_code=exc.code,
                    detail=str(exc),
                    policy_version=exc.policy_version,
                    payload_timestamp=exc.payload_timestamp,
                )
                return command_result(
                    command,
                    status=STATUS_FAILED,
                    detail=f"referenced DevicePolicy rejected: {exc.code}",
                    executed=False,
                )

        if command.command == "SET_THRESHOLD":
            return await self._execute_set_threshold(command)

        logger.error(
            "[runtime] remote command policy/handler mismatch command_id=%s command=%s policy_status=%s",
            command.command_id,
            command.command,
            policy_status,
        )
        return command_result(
            command,
            status=STATUS_UNSUPPORTED,
            detail="execution policy marks command executable but no runtime handler is registered",
            executed=False,
        )

    async def _execute_set_threshold(
        self, command: RemoteCommand
    ) -> RemoteCommandExecutionResult:
        import math

        skill_name = str(command.args.get("skill_name", "") or "").strip()
        threshold_key = str(command.args.get("threshold_key", "") or "").strip()
        raw_value = command.args.get("value")

        if not skill_name or not threshold_key or raw_value is None:
            return command_result(
                command,
                status=STATUS_PRECONDITION_FAILED,
                detail="SET_THRESHOLD requires args.skill_name, args.threshold_key, and args.value",
                executed=False,
            )

        try:
            new_value = float(raw_value)
        except (TypeError, ValueError):
            return command_result(
                command,
                status=STATUS_PRECONDITION_FAILED,
                detail="args.value must be a number",
                executed=False,
            )

        if not math.isfinite(new_value) or new_value <= 0:
            return command_result(
                command,
                status=STATUS_PRECONDITION_FAILED,
                detail="args.value must be a positive finite number",
                executed=False,
            )

        skill = next((s for s in self._loaded_skills if s.name == skill_name), None)
        if skill is None:
            return command_result(
                command,
                status=STATUS_PRECONDITION_FAILED,
                detail=f"skill {skill_name!r} is not loaded",
                executed=False,
            )

        if threshold_key not in skill.config:
            return command_result(
                command,
                status=STATUS_PRECONDITION_FAILED,
                detail=f"threshold key {threshold_key!r} does not exist in skill {skill_name!r} config",
                executed=False,
            )

        old_value = skill.config[threshold_key]

        if not isinstance(old_value, (int, float)) or not math.isfinite(
            float(old_value)
        ):
            return command_result(
                command,
                status=STATUS_PRECONDITION_FAILED,
                detail=f"threshold key {threshold_key!r} in skill {skill_name!r} is not numeric",
                executed=False,
            )

        if threshold_key not in all_trigger_condition_refs(skill):
            return command_result(
                command,
                status=STATUS_PRECONDITION_FAILED,
                detail=f"threshold key {threshold_key!r} is not referenced by any trigger condition in skill {skill_name!r}",
                executed=False,
            )

        if threshold_key in tier_d_config_keys(skill):
            admission = getattr(self._state_store, "history_admission", None)
            if admission is not None and admission.pending > 0:
                # A reading already evaluated may not be stored yet, so the
                # latest stored reading cannot stand for the current condition.
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail="SET_THRESHOLD for a Tier D key waits until every evaluated reading is stored; retry",
                    executed=False,
                )
            readings = await self._latest_readings_for_skill(skill)
            if readings is None:
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail="SET_THRESHOLD for a Tier D key requires StateStore to verify no active condition is suppressed",
                    executed=False,
                )
            startup_value = self._startup_skill_configs.get(skill_name, {}).get(
                threshold_key
            )
            ok, detail = check_tier_d_startup_sensitivity(
                skill,
                threshold_key=threshold_key,
                new_value=new_value,
                startup_value=startup_value,
            )
            if not ok:
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail=detail,
                    executed=False,
                )
            old_config = dict(skill.config)
            new_config = {**skill.config, threshold_key: new_value}
            ok, detail = check_tier_d_condition_suppression(
                skill, threshold_key, old_config, new_config, readings
            )
            if not ok:
                return command_result(
                    command,
                    status=STATUS_PRECONDITION_FAILED,
                    detail=detail,
                    executed=False,
                )

        if command_requests_dry_run(command):
            return command_result(
                command,
                status=STATUS_DRY_RUN,
                detail=f"would update {threshold_key} {old_value} -> {new_value} in skill {skill_name!r}",
                executed=False,
            )

        skill.config[threshold_key] = new_value
        logger.info(
            "[runtime] SET_THRESHOLD applied skill=%s key=%s old=%s new=%s command_id=%s",
            skill_name,
            threshold_key,
            old_value,
            new_value,
            command.command_id,
        )
        return command_result(
            command,
            status=STATUS_EXECUTED,
            detail=f"{threshold_key} updated {old_value} -> {new_value} in skill {skill_name!r}",
            executed=True,
        )

    def _sensor_ids_for_skill(self, skill: Any) -> list[str]:
        """Return config sensor IDs whose type matches any of the skill's sensors_required."""
        if self._config is None:
            return []
        required_types = {
            str(sr.get("type", "") or "").lower()
            for sr in (getattr(skill, "sensors_required", None) or [])
            if sr.get("type")
        }
        return [
            cfg.id
            for cfg in self._config.sensors
            if str(cfg.type or "").lower() in required_types
        ]

    async def _latest_readings_for_skill(
        self, skill: Any
    ) -> list[SensorReading] | None:
        """Return the most recent SensorReading for each skill-associated sensor.

        Returns ``None`` when StateStore is unavailable. Callers performing
        Tier D suppression checks must treat ``None`` as a precondition failure
        (fail-closed) rather than assuming no condition is active.
        """
        if self._state_store is None:
            return None
        readings: list[SensorReading] = []
        for sensor_id in self._sensor_ids_for_skill(skill):
            history = await self._state_store.get_history(sensor_id, limit=1)
            if history:
                readings.append(history[0])
        return readings

    async def _log_remote_command_execution_result(
        self, result: RemoteCommandExecutionResult
    ) -> None:
        if self._state_store is None or not hasattr(
            self._state_store, "log_remote_command_execution"
        ):
            return
        await self._state_store.log_remote_command_execution(
            command_id=result.command_id,
            channel=result.channel,
            command=result.command,
            status=result.status,
            detail=result.detail,
            executed=result.executed,
            executed_at_ms=result.executed_at_ms,
        )

    async def _handle_remote_command_incident(
        self,
        decision: RemoteCommandThrottleDecision,
    ) -> None:
        """Emit a Tier A operator alert for first-seen remote command abuse."""
        logger.warning(
            "[runtime] remote command abuse incident id=%s channel=%s sender=%r count=%d threshold=%d",
            decision.incident_id,
            decision.channel,
            decision.from_number,
            decision.rejection_count,
            decision.threshold,
        )
        try:
            lockout_state = await self._evaluate_lockout_for_sender(
                channel=decision.channel,
                from_number=decision.from_number,
            )
            self._remote_command_lockout_states[
                remote_command_sender_key(
                    channel=decision.channel,
                    from_number=decision.from_number,
                )
            ] = lockout_state.as_dict()
        except Exception:
            logger.exception(
                "[runtime] remote command lockout risk evaluation failed for channel=%s sender=%r",
                decision.channel,
                decision.from_number,
            )
        if self._alert_sender is None:
            return
        message = (
            "ORI SECURITY ALERT: repeated rejected remote commands detected "
            f"from {decision.channel} sender {decision.from_number}. "
            f"{decision.rejection_count} rejected attempts in "
            f"{decision.window_ms // 1000}s. Command feedback has been throttled; "
            "valid signed commands remain allowed."
        )
        alert_ts = now_ms()
        await self._send_or_queue_alert(
            channel=self._primary_alert_channel,
            message=message,
            recipient=self._operator_contact,
            action_tier="A",
            trigger_name="remote_command_abuse",
            original_ts=alert_ts,
            received_at_ms=alert_ts,
            alert_sender=self._alert_sender,
        )

    async def _load_remote_command_lockout_state(self) -> None:
        """Rebuild advisory sender risk from persisted incident history."""
        self._remote_command_lockout_states.clear()
        if self._state_store is None or not hasattr(
            self._state_store,
            "get_recent_remote_command_incident_senders",
        ):
            return

        now = now_ms()
        lockout_cfg = self._remote_command_lockout_config
        since_ms = now - int(lockout_cfg["state_stale_after_ms"])
        try:
            senders = (
                await self._state_store.get_recent_remote_command_incident_senders(
                    since_ms=since_ms,
                    limit=int(lockout_cfg["incident_sender_limit"]),
                )
            )
        except Exception:
            logger.exception(
                "[runtime] failed to load remote command lockout state from incidents"
            )
            return

        for sender in senders:
            channel = str(sender.get("channel", "") or "")
            from_number = str(sender.get("from_number", "") or "")
            if not channel or not from_number:
                continue
            try:
                lockout_state = await self._evaluate_lockout_for_sender(
                    channel=channel,
                    from_number=from_number,
                    now_ms_value=now,
                )
            except Exception:
                logger.exception(
                    "[runtime] remote command lockout risk bootstrap failed for channel=%s sender=%r",
                    channel,
                    from_number,
                )
                continue
            self._remote_command_lockout_states[
                remote_command_sender_key(
                    channel=channel,
                    from_number=from_number,
                )
            ] = lockout_state.as_dict()

    async def _evaluate_lockout_for_sender(
        self,
        *,
        channel: str,
        from_number: str,
        now_ms_value: int | None = None,
    ):
        """Evaluate advisory sender risk with the runtime's normalized config."""
        cfg = self._remote_command_lockout_config
        return await evaluate_remote_command_lockout(
            state_store=self._state_store,
            channel=channel,
            from_number=from_number,
            window_ms=int(cfg["risk_window_ms"]),
            enforcement_enabled=is_truthy(cfg.get("enforcement_enabled", False)),
            elevated_incident_threshold=int(cfg["elevated_incident_threshold"]),
            critical_incident_threshold=int(cfg["critical_incident_threshold"]),
            elevated_rejection_threshold=int(cfg["elevated_rejection_threshold"]),
            critical_rejection_threshold=int(cfg["critical_rejection_threshold"]),
            now_ms_value=now_ms_value,
        )

    async def _start_sms_webhook_if_enabled(
        self, config: Config
    ) -> asyncio.Task | None:
        sms_cfg = config.actions.sms if isinstance(config.actions.sms, dict) else {}
        webhook_cfg = sms_cfg.get("incoming_webhook", {})
        if not isinstance(webhook_cfg, dict):
            return None

        enabled = is_truthy(webhook_cfg.get("enabled", False))
        if not enabled:
            return None

        if self._sms_action is None:
            logger.warning("[runtime] SMS webhook enabled but SMSAction is unavailable")
            return None

        host = str(webhook_cfg.get("host", "127.0.0.1"))
        port = int(webhook_cfg.get("port", 8080))
        path = str(webhook_cfg.get("path", "/webhooks/sms/africastalking"))
        signature_cfg = webhook_cfg.get("signature") or {}
        signature_mode = (
            str(signature_cfg.get("mode", "token_only") or "token_only").lower()
            if isinstance(signature_cfg, dict)
            else "token_only"
        )
        token = str(webhook_cfg.get("token", "") or "").strip()
        if signature_mode != "hmac_required" and not token:
            logger.warning(
                "[runtime] SMS webhook enabled but incoming_webhook.token is empty; "
                "refusing to start unauthenticated public ingress"
            )
            return None

        signature_verifier = self._build_sms_webhook_signature_verifier(webhook_cfg)
        if signature_mode != "token_only" and signature_verifier is None:
            logger.warning(
                "[runtime] SMS webhook signature mode=%s is configured but verifier "
                "could not be built; refusing to start public ingress",
                signature_mode,
            )
            return None

        self._sms_webhook_server = SMSWebhookServer(
            sms_action=self._sms_action,
            host=host,
            port=port,
            path=path,
            token=token,
            signature_verifier=signature_verifier,
            state_store=self._state_store,
            allowed_source_cidrs=list(webhook_cfg.get("allowed_source_cidrs") or []),
        )
        return asyncio.create_task(
            self._sms_webhook_server.serve_until(self._shutdown_event),
            name="sms-webhook",
        )

    def _build_sms_webhook_signature_verifier(
        self, webhook_cfg: dict[str, Any]
    ) -> WebhookSignatureVerifier | None:
        signature_cfg = webhook_cfg.get("signature") or {}
        if not isinstance(signature_cfg, dict):
            return None
        mode = str(signature_cfg.get("mode", "token_only") or "token_only").lower()
        if mode == "token_only":
            return None
        try:
            config = WebhookSignatureConfig(
                mode=mode,
                shared_secret=str(signature_cfg.get("shared_secret", "") or ""),
                previous_shared_secret=str(
                    signature_cfg.get("previous_shared_secret", "") or ""
                ),
                signature_header=str(
                    signature_cfg.get("signature_header", "x-ori-webhook-signature")
                    or "x-ori-webhook-signature"
                ),
                timestamp_header=str(
                    signature_cfg.get("timestamp_header", "x-ori-webhook-timestamp")
                    or "x-ori-webhook-timestamp"
                ),
                nonce_header=str(
                    signature_cfg.get("nonce_header", "x-ori-webhook-nonce")
                    or "x-ori-webhook-nonce"
                ),
                max_skew_ms=int(signature_cfg.get("max_skew_seconds", 300)) * 1000,
                replay_ttl_ms=int(signature_cfg.get("replay_ttl_seconds", 300)) * 1000,
                require_nonce=is_truthy(signature_cfg.get("require_nonce", True)),
            )
            return WebhookSignatureVerifier(config)
        except Exception:
            logger.exception(
                "[runtime] invalid SMS webhook signature configuration; refusing to "
                "start signed webhook ingress"
            )
            return None
