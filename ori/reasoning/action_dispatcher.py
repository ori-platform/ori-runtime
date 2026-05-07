# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Action Dispatcher — the agent's executor.

Routes every :class:`~ori.network.events.ReasoningResult` to the appropriate
execution path based on its action tier:

- **Tier A** (Informational): execute immediately, no approval.
- **Tier B** (Soft Physical): execute immediately *unless* ``requires_approval``
  is ``True`` in the skill config, in which case run the approval workflow.
- **Tier C** (Hard Physical): approval workflow **always**.  No exception.
- **Tier D** (Safety-Critical): execute immediately, highest priority.

Every dispatch attempt produces an :class:`~ori.network.events.ActionResult`
and is logged to the ``action_log`` table — even on failure.  A failed action
must never crash the runtime.
"""

import asyncio
import datetime
import logging
from typing import Any

from ori.actions.logger import LoggerAction
from ori.network.events import ActionResult, ActionTier, ReasoningResult
from ori.policy.device_policy import DevicePolicy
from ori.reasoning.capability_posture import CapabilityPosture
from ori.reasoning.elevator import SkillContext
from ori.security.offline_tokens import OfflineTierCTokenVerifier
from ori.time_utils import now_ms

logger = logging.getLogger(__name__)

_YES_TOKENS = frozenset({"yes", "y", "approve", "go", "ok", "confirm"})
_NO_TOKENS = frozenset({"no", "n", "cancel", "stop", "reject", "deny"})

_DEFAULT_APPROVAL_TIMEOUT = 300  # seconds
_DEFAULT_SAFE_DEFAULT_ACTION = "log_to_dashboard"
_TIER_RANK: dict[str, int] = {
    ActionTier.INFORMATIONAL: 1,
    ActionTier.SOFT_PHYSICAL: 2,
    ActionTier.HARD_PHYSICAL: 3,
    ActionTier.SAFETY_CRITICAL: 4,
}


def _parse_approval_response(response: str | None) -> bool:
    """Return ``True`` if *response* is an affirmative approval token.

    Args:
        response: Raw operator reply string, or ``None``.

    Returns:
        ``True`` if the response is YES/Y/approve/go/ok/confirm
        (case-insensitive).  ``False`` for NO tokens, ``None``, or
        anything unrecognised.
    """
    if response is None:
        return False
    token = response.strip().lower()
    return token in _YES_TOKENS


def _tier_rank(tier: str) -> int:
    return _TIER_RANK.get(str(tier).upper(), 0)


class ActionDispatcher:
    """Routes reasoning results to execution paths based on action tier.

    Action executors (WhatsApp, SMS, relay, etc.) are registered via
    :meth:`register_executor`.  If no executor is registered for an action
    name, the action is logged as not-executed and the dispatcher moves on.

    Args:
        state_store: :class:`~ori.state.store.StateStore` for logging.
            Falls back to ``context.state_store`` at dispatch time if not set.
        alert_sender: Object with ``send(message: str, to_number: str) -> Awaitable``
            used to deliver approval messages. ``None`` disables the approval
            workflow (actions fall back to safe_default immediately).
        config: Dispatcher-level config dict.  Recognised keys:
            ``operator_contact`` (str), ``secondary_contact`` (str),
            ``approval_timeout_seconds`` (int), ``primary_alert_channel`` (str).
    """

    def __init__(
        self,
        state_store: Any = None,
        alert_sender: Any = None,
        emergency_sms_sender: Any = None,
        offline_token_verifier: OfflineTierCTokenVerifier | None = None,
        status_indicator: Any = None,
        config: dict | None = None,
    ) -> None:
        self._state_store = state_store
        self._alert_sender = alert_sender
        self._emergency_sms_sender = emergency_sms_sender
        self._offline_token_verifier = offline_token_verifier
        self._config: dict = config or {}
        self._log_action_decisions = bool(
            self._config.get("log_action_decisions", True)
        )
        self._log_approval_workflow = bool(
            self._config.get("log_approval_workflow", True)
        )
        self._relay_b_c_enabled = bool(self._config.get("relay_enabled", False))
        self._local_console_enabled = bool(
            self._config.get("local_console_enabled", False)
        )
        self._local_console_poll_interval_ms = max(
            100, int(self._config.get("local_console_poll_interval_ms", 1000))
        )
        self._local_console_channel_id = str(
            self._config.get("local_console_channel_id", "local_console")
        )
        self._policy: DevicePolicy | None = DevicePolicy.unrestricted()
        self._capability_posture: CapabilityPosture | None = None
        self._status_indicator = status_indicator
        self._logger_action = LoggerAction()
        self._inflight_tier_d_tasks: set[asyncio.Task[Any]] = set()
        self._executors: dict[str, Any] = {
            # Built-in fallback for test environments.
            # OriRuntime.start() overwrites this with a closure
            # that has the real config.device.id from the deployment.
            "log_to_dashboard": self._log_to_dashboard_executor,
        }

    # ── Public API ────────────────────────────────────────────────────────────

    def register_executor(self, action_name: str, executor: Any) -> None:
        """Register a callable for *action_name*.

        The callable must be an async function with signature::

            async def execute(action: str, context: SkillContext) -> None

        Args:
            action_name: The action identifier (e.g. ``'alert_whatsapp'``).
            executor: Async callable invoked when the action fires.
        """
        self._executors[action_name] = executor

    def update_policy(self, policy: DevicePolicy | None) -> None:
        """Update the active DevicePolicy.

        ``None`` resets to unrestricted self-hosted behaviour.
        """
        self._policy = policy if policy is not None else DevicePolicy.unrestricted()
        self._sync_policy_led_state()

    def update_capability_posture(self, posture: CapabilityPosture | None) -> None:
        self._capability_posture = posture

    def current_policy_version(self) -> int | None:
        if self._policy is None:
            return None
        return int(self._policy.policy_version)

    def permits_relay_action(self, action_tier: str) -> bool:
        """Check if a relay action is permitted for the given tier based on DevicePolicy and config."""
        if action_tier == ActionTier.SAFETY_CRITICAL:
            return True  # Invariant 10: Tier D is never blocked
        if action_tier == ActionTier.INFORMATIONAL:
            return True  # Tier A informational always permitted
        active_policy = (
            self._policy if self._policy is not None else DevicePolicy.unrestricted()
        )
        return self._relay_b_c_enabled and active_policy.permits_action(action_tier)

    def get_inflight_tier_d_tasks(self) -> set[asyncio.Task[Any]]:
        """Return currently running Tier D execution tasks."""
        return {task for task in self._inflight_tier_d_tasks if not task.done()}

    def _track_tier_d_task(self, task: asyncio.Task[Any]) -> None:
        self._inflight_tier_d_tasks.add(task)
        task.add_done_callback(self._inflight_tier_d_tasks.discard)

    async def dispatch(
        self,
        action: str,
        tier: str,
        context: SkillContext,
        result: ReasoningResult,
        safe_default_action: str = _DEFAULT_SAFE_DEFAULT_ACTION,
        approval_timeout: int | None = None,
        approval_timeout_seconds: int | None = None,
    ) -> ActionResult:
        """Route *action* to the correct execution path for *tier*.

        Tier routing:

        - **D**: :meth:`_execute_immediately` — no approval, immediate.
        - **A**: :meth:`_execute_immediately`.
        - **B**: :meth:`_execute_immediately`, unless
          ``context.skill.config.get('requires_approval')`` is truthy, in
          which case :meth:`_approval_workflow`.
        - **C**: :meth:`_approval_workflow` — always, no exception.

        All exceptions are caught.  An :class:`~ori.network.events.ActionResult`
        is always returned and logged.

        Args:
            action: Action name (e.g. ``'alert_whatsapp'``).
            tier: Action tier — ``'A'`` | ``'B'`` | ``'C'`` | ``'D'``.
            context: :class:`~ori.reasoning.elevator.SkillContext` carrying
                the skill, event, and state_store.
            result: The :class:`~ori.network.events.ReasoningResult` from
                the Intelligence Elevator.
            safe_default_action: Action to execute on Tier C approval timeout
                or NO response.  Overrides the dispatcher default.
            approval_timeout: Seconds to wait for operator approval before
                executing *safe_default_action*.
            approval_timeout_seconds: Backward-compatible alias for
                ``approval_timeout``.

        Returns:
            :class:`~ori.network.events.ActionResult` describing what happened.
        """
        # Double-check against skill action capability tiers.
        # This is an escalation-only guardrail: it may raise a tier, never lower it.
        if context and hasattr(context, "skill") and hasattr(context.skill, "actions"):
            if "available" in context.skill.actions:
                for avail_action in context.skill.actions["available"]:
                    if avail_action.get("name") == action and avail_action.get("tier"):
                        defined_tier = str(avail_action["tier"]).upper()
                        if tier == ActionTier.SAFETY_CRITICAL:
                            break
                        incoming_rank = _tier_rank(tier)
                        defined_rank = _tier_rank(defined_tier)
                        if defined_rank > incoming_rank:
                            logger.debug(
                                "ActionDispatcher: escalating action %r from Tier %s to Tier %s "
                                "based on skill capability declaration",
                                action,
                                tier,
                                defined_tier,
                            )
                            tier = defined_tier
                        elif 0 < defined_rank < incoming_rank:
                            logger.warning(
                                "ActionDispatcher: refusing to downgrade action %r from Tier %s "
                                "to Tier %s from capability declaration",
                                action,
                                tier,
                                defined_tier,
                            )
                        break

        # Log autonomous Tier D dispatch to override_log before execution —
        # a safety-critical action firing without operator approval is itself
        # an override event that must be auditable.
        timeout_value = approval_timeout
        if timeout_value is None:
            timeout_value = (
                approval_timeout_seconds
                if approval_timeout_seconds is not None
                else _DEFAULT_APPROVAL_TIMEOUT
            )
        try:
            timeout_value = int(timeout_value)
        except (TypeError, ValueError):
            timeout_value = _DEFAULT_APPROVAL_TIMEOUT

        # Tier D Bypass and Policy restrictions for B/C relay actions
        if action in ("trip_relay", "release_relay") and tier in (
            ActionTier.SOFT_PHYSICAL,
            ActionTier.HARD_PHYSICAL,
        ):
            if not self.permits_relay_action(tier):
                # Persist explicit suppression audit before fallback rewrite so
                # the original attempted relay action is preserved in action_log.
                suppression_result = ActionResult(
                    action_name=action,
                    tier=tier,
                    executed=False,
                    approved=None,
                    action_taken="suppressed",
                    timestamp=now_ms(),
                    operator_response="policy_suppression",
                )
                await self._log_action(suppression_result, context)
                logger.warning(
                    "ActionDispatcher: %r suppressed for Tier %s due to relay.enabled or DevicePolicy restriction. Downgrading to safe default.",
                    action,
                    tier,
                )

                action = safe_default_action
                tier = ActionTier.INFORMATIONAL

        if tier == ActionTier.SAFETY_CRITICAL:
            _store = (
                context.state_store
                if hasattr(context, "state_store") and context.state_store is not None
                else self._state_store
            )
            if _store is not None and hasattr(_store, "log_override"):
                _device_id = context.event.device_id if context.event else "unknown"
                try:
                    await _store.log_override(
                        trigger_name=context.event.sensor_id if context.event else "",
                        action=action,
                        reason="autonomous_tier_d_safety_action",
                        operator_response=None,
                        override_type="autonomous_tier_d",
                        device_id=_device_id,
                    )
                except Exception:
                    logger.exception(
                        "ActionDispatcher: failed to log Tier D override for action=%r",
                        action,
                    )

        try:
            if tier == ActionTier.SAFETY_CRITICAL:
                if self._status_indicator is not None:
                    self._status_indicator.set_tier_d_firing()
                # Track Tier D work explicitly so runtime shutdown can drain it
                # without relying on fragile task attribute mutation.
                inner_task = asyncio.create_task(
                    self._execute_immediately(action, tier, context)
                )
                self._track_tier_d_task(inner_task)
                action_result = await asyncio.shield(inner_task)
                if self._status_indicator is not None:
                    self._status_indicator.clear_tier_d_firing()

            elif tier == ActionTier.INFORMATIONAL:
                action_result = await self._execute_immediately(action, tier, context)

            elif tier == ActionTier.SOFT_PHYSICAL:
                requires_approval = False
                if hasattr(context, "skill") and hasattr(context.skill, "config"):
                    requires_approval = bool(
                        context.skill.config.get("requires_approval", False)
                    )
                if requires_approval:
                    action_result = await self._approval_workflow(
                        action,
                        tier,
                        context,
                        result,
                        safe_default_action,
                        timeout_value,
                    )
                else:
                    action_result = await self._execute_immediately(
                        action, tier, context
                    )

            elif tier == ActionTier.HARD_PHYSICAL:
                # Always approval workflow — no exception, no config override
                action_result = await self._approval_workflow(
                    action,
                    tier,
                    context,
                    result,
                    safe_default_action,
                    timeout_value,
                )

            else:
                if self._log_action_decisions:
                    logger.warning(
                        "ActionDispatcher: unknown action tier %r for action=%r — "
                        "treating as Tier A",
                        tier,
                        action,
                    )
                action_result = await self._execute_immediately(action, tier, context)

        except (Exception, asyncio.CancelledError) as exc:
            # asyncio.CancelledError is BaseException, not Exception.
            # We must catch it explicitly here so that a runtime shutdown
            # during a Tier D dispatch does not silently abandon the action.
            # For Tier D specifically, log at CRITICAL level.
            if tier == ActionTier.SAFETY_CRITICAL:
                logger.critical(
                    "ActionDispatcher: Tier D action=%r was interrupted "
                    "(%s) — physical safety action may not have executed. "
                    "Manual intervention may be required.",
                    action,
                    type(exc).__name__,
                )
            else:
                logger.exception(
                    "ActionDispatcher: unhandled exception dispatching "
                    "action=%r tier=%r",
                    action,
                    tier,
                )
            action_result = ActionResult(
                action_name=action,
                tier=tier,
                executed=False,
                approved=None,
                action_taken="",
                timestamp=now_ms(),
            )
            if (
                tier == ActionTier.SAFETY_CRITICAL
                and self._status_indicator is not None
            ):
                self._status_indicator.clear_tier_d_firing()

        await self._log_action(action_result, context)
        return action_result

    # ── Built-in executors ────────────────────────────────────────────────────

    async def _log_to_dashboard_executor(
        self, action: str, context: SkillContext
    ) -> None:
        """Built-in executor for ``log_to_dashboard``.

        Used as the safe default for Tier C timeouts and operator rejections.
        Delegates to :class:`~ori.actions.logger.LoggerAction` so the fallback
        path is always auditable even when no external alert channel is wired.
        """
        device_id = context.event.device_id if context and context.event else "unknown"
        self._logger_action.log_override(
            action=action,
            override_type="safe_default",
            device_id=device_id,
        )

    # ── Execution paths ───────────────────────────────────────────────────────

    async def _execute_immediately(
        self,
        action: str,
        tier: str,
        context: SkillContext,
    ) -> ActionResult:
        """Execute *action* without any approval step.

        If an executor is registered for *action*, it is called.  If no
        executor exists, the action is logged as executed (the intent is
        recorded even if no physical action fired).

        Args:
            action: Action name to execute.
            tier: Action tier (passed through to the result).
            context: Skill execution context.

        Returns:
            :class:`~ori.network.events.ActionResult` with ``executed=True``
            on success and ``executed=False`` if the executor raised.
        """
        executed = True
        try:
            executor = self._executors.get(action)
            if executor is not None:
                if self._log_action_decisions:
                    logger.info(
                        "ActionDispatcher: executing action %r (tier=%s)", action, tier
                    )
                maybe_ok = await executor(action, context)
                if maybe_ok is False:
                    executed = False
            else:
                if (
                    action in ("trip_relay", "release_relay")
                    and tier == ActionTier.SAFETY_CRITICAL
                ):
                    executed = False
                    logger.critical(
                        "ActionDispatcher: Tier D relay executor is not registered (hardware initialization failed)."
                    )
                elif self._log_action_decisions:
                    logger.debug(
                        "ActionDispatcher: no executor registered for action=%r — "
                        "logging intent only",
                        action,
                    )
        except (Exception, asyncio.CancelledError) as exc:
            if tier == ActionTier.SAFETY_CRITICAL:
                logger.critical(
                    "ActionDispatcher: Tier D executor failed for action=%r — %s: %s",
                    action,
                    type(exc).__name__,
                    exc,
                )
            else:
                logger.exception(
                    "ActionDispatcher: executor raised for action=%r", action
                )
            executed = False

        if not executed and tier == ActionTier.SAFETY_CRITICAL:
            logger.critical(
                "TIER D ACTION FAILED: action=%r could not execute. "
                "Physical safety action was not taken. "
                "Manual intervention required immediately.",
                action,
            )
            device_id = (
                getattr(context.event, "device_id", "unknown")
                if context and context.event
                else "unknown"
            )
            await self._emergency_sms(action, device_id)

        return ActionResult(
            action_name=action,
            tier=tier,
            executed=executed,
            approved=None,  # no approval step for A/B/D
            action_taken=action if executed else "",
            timestamp=now_ms(),
        )

    async def _approval_workflow(
        self,
        action: str,
        tier: str,
        context: SkillContext,
        result: ReasoningResult,
        safe_default_action: str,
        approval_timeout_seconds: int,
    ) -> ActionResult:
        """Send an approval request and wait for YES/NO from the operator.

        Flow:

        1. Format and send the approval message via ``_alert_sender``.
        2. Await :meth:`_listen_for_response` with *approval_timeout_seconds*.
        3. Parse the response:
           - YES/approve → :meth:`_execute_immediately` with original *action*.
           - NO/cancel or ``None`` → :meth:`_execute_immediately` with
             *safe_default_action*.
        4. On timeout: execute *safe_default_action*; escalate to secondary
           contact if configured.

        Args:
            action: The proposed action awaiting approval.
            tier: Action tier.
            context: Skill execution context.
            result: Reasoning result for message formatting.
            safe_default_action: Fallback action on timeout/NO.
            approval_timeout_seconds: Approval wait window.

        Returns:
            :class:`~ori.network.events.ActionResult` with ``approved`` set to
            ``True`` / ``False`` based on the operator response.
        """
        if self._log_approval_workflow:
            logger.info(
                "ActionDispatcher: triggering Tier C approval workflow for action=%r",
                action,
            )
        has_comms = self._tier_c_comms_available()
        if self._status_indicator is not None:
            self._status_indicator.set_tier_c_pending(has_comms=has_comms)

        device_id = context.event.device_id if context.event else "unknown"
        message = self._format_approval_message(
            device_id=device_id,
            timestamp_ms=context.event.timestamp if context.event else now_ms(),
            result=result,
            action=action,
            timeout_seconds=approval_timeout_seconds,
            device_timezone=self._config.get("device_timezone", "Africa/Lagos"),
        )

        # Send approval request (best-effort only when comms are available).
        operator_contact = self._config.get("operator_contact", "")
        if has_comms and self._alert_sender is not None and operator_contact:
            try:
                await self._alert_sender.send(
                    message=message, to_number=operator_contact
                )
            except Exception:
                logger.exception(
                    "ActionDispatcher: failed to send approval request for action=%r",
                    action,
                )

        # Wait for response
        operator_response: str | None = None
        parsed_operator_response: str | None = None
        timed_out = False
        local_console_mode = bool(not has_comms and self._local_console_enabled)
        store = self._resolve_state_store(context)
        if local_console_mode:
            local_from_number = operator_contact or "local-operator"
            operator_response = await self._listen_for_local_console_response(
                store=store,
                from_number=local_from_number,
                timeout_seconds=approval_timeout_seconds,
            )
            parsed_operator_response = operator_response
            if operator_response is not None:
                operator_response = f"LOCAL:{operator_response}"
            else:
                timed_out = True
                logger.warning(
                    "ActionDispatcher: local console approval timeout for action=%r "
                    "after %ds — executing safe_default=%r",
                    action,
                    approval_timeout_seconds,
                    safe_default_action,
                )
        else:
            try:
                listen_coro = self._listen_for_response(
                    from_number=operator_contact,
                    timeout_seconds=approval_timeout_seconds,
                )
            except TypeError:
                # Backward compatibility for older test doubles/overrides that
                # patched _listen_for_response with a no-arg coroutine.
                listen_coro = self._listen_for_response()  # type: ignore[call-arg]
            listen_task = asyncio.create_task(
                listen_coro,
                name=f"approval:{action}",
            )
            try:
                operator_response = await asyncio.wait_for(
                    listen_task,
                    # Keep a small guard margin around provider-side timeout logic.
                    timeout=float(approval_timeout_seconds) + 1.0,
                )
                parsed_operator_response = operator_response
            except asyncio.TimeoutError:
                timed_out = True
                if not listen_task.done():
                    listen_task.cancel()
                logger.warning(
                    "ActionDispatcher: approval timeout for action=%r after %ds — "
                    "executing safe_default=%r",
                    action,
                    approval_timeout_seconds,
                    safe_default_action,
                )
            else:
                if operator_response is None:
                    timed_out = True
                    logger.warning(
                        "ActionDispatcher: no approval response for action=%r within %ds — "
                        "executing safe_default=%r",
                        action,
                        approval_timeout_seconds,
                        safe_default_action,
                    )

        try:
            # Parse response
            approved = _parse_approval_response(parsed_operator_response)
            if (
                local_console_mode
                and parsed_operator_response is not None
                and parsed_operator_response.strip().upper().startswith("TOKEN:")
            ):
                token_value = parsed_operator_response.split(":", 1)[1].strip()
                if self._offline_token_verifier is None:
                    approved = False
                    logger.warning(
                        "ActionDispatcher: offline token provided but verifier is disabled"
                    )
                else:
                    verify_result = await self._offline_token_verifier.verify_token(
                        token_value,
                        expected_device_id=device_id,
                        expected_action=action,
                        state_store=store,
                    )
                    approved = bool(verify_result.approved)
                    if approved:
                        operator_response = (
                            f"LOCAL:TOKEN_APPROVED:{verify_result.token_id}"
                        )
                    else:
                        operator_response = (
                            f"LOCAL:TOKEN_REJECTED:{verify_result.reason}"
                        )
                        logger.warning(
                            "ActionDispatcher: offline token rejected for action=%r reason=%s",
                            action,
                            verify_result.reason,
                        )

            if approved:
                inner = await self._execute_immediately(action, tier, context)
                action_taken = inner.action_taken
                executed = inner.executed
            else:
                # NO, None, or timeout → safe default
                if timed_out:
                    await self._escalate_to_secondary(action, context, result)
                inner = await self._execute_immediately(
                    safe_default_action, tier, context
                )
                action_taken = inner.action_taken
                executed = inner.executed
                # Log operator rejection / timeout override to override_log
                if store is not None and hasattr(store, "log_override"):
                    device_id = context.event.device_id if context.event else "unknown"
                    await store.log_override(
                        trigger_name=context.event.sensor_id if context.event else "",
                        action=action,
                        reason="timeout" if timed_out else "operator_rejection",
                        operator_response=operator_response,
                        override_type="rejection",
                        device_id=device_id,
                    )
                if not timed_out and operator_response is not None:
                    await self._store_rejection_pattern(
                        store=store,
                        action=action,
                        context=context,
                        operator_response=operator_response,
                    )

            return ActionResult(
                action_name=action,
                tier=tier,
                executed=executed,
                approved=approved,
                action_taken=action_taken,
                timestamp=now_ms(),
                operator_response=operator_response,
            )
        finally:
            if self._status_indicator is not None:
                self._status_indicator.clear_tier_c_pending()

    async def _listen_for_local_console_response(
        self,
        *,
        store: Any,
        from_number: str,
        timeout_seconds: int,
    ) -> str | None:
        """Poll local inbound channel for Tier C approval replies."""
        if store is None or not hasattr(store, "consume_incoming_message"):
            return None

        timeout_ms = max(0, int(timeout_seconds) * 1000)
        since_ms = now_ms()
        deadline_ms = since_ms + timeout_ms
        channel = self._local_console_channel_id
        poll_s = self._local_console_poll_interval_ms / 1000.0
        while True:
            try:
                response = await store.consume_incoming_message(
                    channel=channel,
                    from_number=from_number,
                    since_ms=since_ms,
                )
            except Exception:
                logger.exception(
                    "ActionDispatcher: local console approval listener failed"
                )
                return None
            if response is not None:
                return response
            if now_ms() >= deadline_ms:
                return None
            await asyncio.sleep(poll_s)

    async def _store_rejection_pattern(
        self,
        store: Any,
        action: str,
        context: SkillContext,
        operator_response: str,
    ) -> None:
        """Persist a rejected Tier C pattern for future informational capping."""
        if store is None:
            return
        if not hasattr(type(store), "store_rejection") or not hasattr(
            type(store), "_build_rejection_pattern_key"
        ):
            return
        store_rejection = getattr(store, "store_rejection", None)
        key_builder = getattr(store, "_build_rejection_pattern_key", None)
        if not callable(store_rejection) or not callable(key_builder):
            return
        if context is None or context.event is None or context.event.reading is None:
            return

        reading = context.event.reading
        evt = context.event
        trigger_name = ""
        if isinstance(getattr(evt, "context", None), dict):
            trigger_name = str(evt.context.get("__handler_trigger_name") or "")
        if not trigger_name:
            trigger_name = str(evt.sensor_id or "unknown_trigger")

        value_bucket = round(float(reading.value) * 2.0) / 2.0
        dt = datetime.datetime.fromtimestamp(
            evt.timestamp / 1000.0, tz=datetime.timezone.utc
        )
        hour_bucket = (dt.hour // 2) * 2
        day_of_week = dt.weekday()

        try:
            pattern_key = key_builder(
                reading.sensor_type,
                trigger_name,
                action,
                float(reading.value),
                int(evt.timestamp),
            )
            maybe_coro = store_rejection(
                pattern_key=pattern_key,
                trigger_name=trigger_name,
                proposed_action=action,
                operator_response=operator_response,
                device_id=str(evt.device_id or "unknown"),
                sensor_type=str(reading.sensor_type or ""),
                value_bucket=value_bucket,
                time_of_day_hour=hour_bucket,
                day_of_week=day_of_week,
                expiry_days=int(self._config.get("rejection_expiry_days", 30)),
            )
            if asyncio.iscoroutine(maybe_coro):
                await maybe_coro
            logger.info(
                "Rejection stored for pattern %s — future identical patterns capped at Tier A",
                pattern_key,
            )
        except Exception:
            logger.exception(
                "ActionDispatcher: failed to persist rejection pattern for action=%r",
                action,
            )

    async def _listen_for_response(
        self, from_number: str, timeout_seconds: int
    ) -> str | None:
        """Delegate operator response listening to the configured alert sender.

        Returns:
            Operator reply text, or ``None`` when no reply is received or
            when no compatible listener is configured.
        """
        if not self._alert_sender or not from_number:
            return None

        listener = getattr(self._alert_sender, "listen_for_response", None)
        if listener is None:
            logger.warning(
                "ActionDispatcher: alert_sender has no listen_for_response() method"
            )
            return None

        try:
            return await listener(
                from_number=from_number,
                timeout_seconds=timeout_seconds,
            )
        except TypeError:
            # Compatibility with listeners that only accept positional args.
            return await listener(from_number, timeout_seconds)
        except Exception:
            logger.exception(
                "ActionDispatcher: failed while listening for operator response"
            )
            return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _format_approval_message(
        self,
        device_id: str,
        timestamp_ms: int,
        result: ReasoningResult,
        action: str,
        timeout_seconds: int,
        device_timezone: str = "Africa/Lagos",
    ) -> str:
        """Format the WhatsApp/SMS approval request message.

        Args:
            device_id: The device that triggered the action.
            timestamp_ms: Unix milliseconds timestamp.
            result: The reasoning result with text and confidence.
            action: The proposed action name.
            timeout_seconds: Auto-cancel window.
            device_timezone: IANA timezone name for local time display
                (e.g. ``"Africa/Lagos"``).  Defaults to WAT so operators in
                Nigeria see their local time, not UTC.

        Returns:
            Formatted approval message string matching the README template.
        """
        from zoneinfo import ZoneInfo

        tz = ZoneInfo(device_timezone or "Africa/Lagos")
        dt = datetime.datetime.fromtimestamp(timestamp_ms / 1000, tz=tz)
        formatted_time = dt.strftime("%A %H:%M")  # e.g. "Wednesday 14:32"

        observation = result.text
        reasoning = result.reasoning if result.reasoning else result.text

        return (
            f"ORI ALERT — Action Required\n"
            f"Device: {device_id}\n"
            f"Time: {formatted_time}\n"
            f"\n"
            f"OBSERVATION:\n"
            f"{observation}\n"
            f"\n"
            f"REASONING:\n"
            f"{reasoning}\n"
            f"\n"
            f"PROPOSED ACTION:\n"
            f"{action}\n"
            f"\n"
            f"CONFIDENCE: {result.confidence:.0%}\n"
            f"\n"
            f"Reply YES to approve  |  Reply NO to cancel\n"
            f"Auto-cancel in {timeout_seconds} seconds if no response."
        )

    async def _escalate_to_secondary(
        self,
        action: str,
        context: SkillContext,
        result: ReasoningResult,
    ) -> None:
        """Notify the secondary contact when a Tier C approval times out.

        No-op if no secondary contact is configured or alert_sender is absent.

        Args:
            action: The action that timed out.
            context: Skill execution context.
            result: Reasoning result for message context.
        """
        secondary = self._config.get("secondary_contact", "")
        if not secondary or self._alert_sender is None:
            return
        device_id = context.event.device_id if context.event else "unknown"
        message = (
            f"ORI ESCALATION — Tier C approval timed out\n"
            f"Device: {device_id}\n"
            f"Action: {action}\n"
            f"Safe default was executed.\n"
            f"Observation: {result.text}"
        )
        try:
            await self._alert_sender.send(message=message, to_number=secondary)
        except Exception:
            logger.exception(
                "ActionDispatcher: failed to send escalation to secondary contact"
            )

    async def _emergency_sms(self, action: str, device_id: str) -> None:
        """Last-resort SMS when a Tier D safety action fails to execute.

        Uses :class:`~ori.actions.sms.SMSAction` directly — independent of
        ``_alert_sender`` so that a misconfigured alert channel does not
        prevent the emergency notification.  Never raises.

        Args:
            action: The Tier D action name that failed.
            device_id: The device on which the failure occurred.
        """
        try:
            sms = self._emergency_sms_sender
            if sms is None:
                from ori.actions.sms import SMSAction

                sms = SMSAction()
            contact = self._config.get("operator_contact", "")
            if not contact:
                logger.critical(
                    "ActionDispatcher: no operator_contact configured — "
                    "cannot send emergency SMS for failed Tier D action=%r",
                    action,
                )
                return
            await sms.send(
                f"CRITICAL: Ori safety action '{action}' FAILED to execute "
                f"on device {device_id}. Manual intervention required immediately.",
                to_number=contact,
            )
        except Exception:
            logger.exception(
                "ActionDispatcher: emergency SMS also failed for action=%r",
                action,
            )

    def _sync_policy_led_state(self) -> None:
        if self._status_indicator is None:
            return
        if self._policy is None:
            self._status_indicator.set_policy_state("restricted")
            return
        if self._policy.is_expired:
            self._status_indicator.set_policy_state("restricted")
            return
        if self._policy.signature == "self_hosted":
            self._status_indicator.set_policy_state("normal")
            return
        if not (
            self._policy.relay_b_enabled
            and self._policy.relay_c_enabled
            and self._policy.cloud_llm_enabled
        ):
            self._status_indicator.set_policy_state("grace")
            return
        self._status_indicator.set_policy_state("normal")

    def _tier_c_comms_available(self) -> bool:
        if self._capability_posture is not None:
            return bool(
                self._capability_posture.sms_available
                or self._capability_posture.whatsapp_available
            )
        return bool(
            self._alert_sender is not None and self._config.get("operator_contact")
        )

    async def _log_action(
        self,
        action_result: ActionResult,
        context: SkillContext,
    ) -> None:
        """Persist *action_result* to the ``action_log`` table.

        Uses ``context.state_store`` first; falls back to the dispatcher's own
        ``_state_store``.  Silently skips logging if no store is available.

        Args:
            action_result: The result to persist.
            context: Skill execution context (carries state_store).
        """
        store = None
        if hasattr(context, "state_store") and context.state_store is not None:
            store = context.state_store
        elif self._state_store is not None:
            store = self._state_store

        if store is None:
            return

        trigger_name = context.event.sensor_id if context.event else ""
        try:
            await store.log_action(action_result, trigger_name)
        except Exception:
            logger.exception(
                "ActionDispatcher: failed to log action=%r to action_log",
                action_result.action_name,
            )

    def _resolve_state_store(self, context: SkillContext) -> Any:
        if hasattr(context, "state_store") and context.state_store is not None:
            return context.state_store
        return self._state_store
