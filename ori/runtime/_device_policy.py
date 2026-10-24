# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""DevicePolicy: the cached policy at startup, the remote refresh, and its audit."""

import asyncio
import json
import logging
from typing import Any

from ori.config import Config
from ori.policy.remote_fetch import (
    RemotePolicyFetchError,
    device_policy_from_payload,
    fetch_remote_device_policy_bundle,
)
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.runtime._constants import DEVICE_POLICY_TRANSIENT_AUDIT_SUPPRESS_MS
from ori.runtime._core import RuntimeCore
from ori.skills.signing import verify_signed_payload
from ori.utils.strict_json import unique_members
from ori.utils.time_utils import now_ms

logger = logging.getLogger("ori.runtime")


class DevicePolicyRefresh(RuntimeCore):
    """Loading, refreshing and auditing DevicePolicy."""

    async def _maybe_refresh_remote_device_policy_once(
        self,
        config: Config,
        dispatcher: ActionDispatcher,
    ) -> None:
        """Optionally fetch and apply a verified remote DevicePolicy once at startup."""
        policy_cfg = (
            config.device_policy if isinstance(config.device_policy, dict) else {}
        )
        if not bool(policy_cfg.get("enabled", False)):
            return

        await self._refresh_remote_device_policy_once(
            config=config,
            dispatcher=dispatcher,
            suppress_transient_audit=False,
        )

    async def _refresh_remote_device_policy_once(
        self,
        *,
        config: Config,
        dispatcher: ActionDispatcher,
        suppress_transient_audit: bool,
    ) -> bool:
        current_version = dispatcher.current_policy_version()
        try:
            fetched = await fetch_remote_device_policy_bundle(
                config.device_policy,
                current_policy_version=current_version,
            )
            await self._apply_fetched_remote_device_policy(
                config=config,
                fetched=fetched,
                dispatcher=dispatcher,
            )
            return True
        except RemotePolicyFetchError as exc:
            logger.warning(
                "[runtime] remote DevicePolicy rejected code=%s detail=%s",
                exc.code,
                str(exc),
            )
            if (
                suppress_transient_audit
                and self._should_suppress_transient_policy_audit(
                    reason_code=exc.code,
                    detail=str(exc),
                )
            ):
                return False
            await self._audit_policy_rejection(
                device_id=config.device.id,
                reason_code=exc.code,
                detail=str(exc),
                policy_version=exc.policy_version,
                payload_timestamp=exc.payload_timestamp,
            )
            return False
        except Exception:
            logger.exception("[runtime] unexpected remote DevicePolicy fetch error")
            await self._audit_policy_rejection(
                device_id=config.device.id,
                reason_code="unexpected_error",
                detail="unexpected exception during remote policy fetch",
                policy_version=None,
                payload_timestamp=None,
            )
            return False

    async def _apply_fetched_remote_device_policy(
        self,
        *,
        config: Config,
        fetched: Any,
        dispatcher: ActionDispatcher,
    ) -> None:
        """Apply a previously verified remote DevicePolicy and cache it."""
        dispatcher.update_policy(fetched.policy)
        logger.info(
            "[runtime] remote DevicePolicy applied — version=%s tier=%s valid_until=%s",
            fetched.policy.policy_version,
            fetched.policy.tier,
            fetched.policy.valid_until,
        )
        if self._state_store is None:
            return
        try:
            await self._state_store.upsert_device_policy_cache(
                policy_version=fetched.policy.policy_version,
                tier=fetched.policy.tier,
                relay_b_enabled=fetched.policy.relay_b_enabled,
                relay_c_enabled=fetched.policy.relay_c_enabled,
                cloud_llm_enabled=fetched.policy.cloud_llm_enabled,
                valid_until=fetched.policy.valid_until,
                issued_at=fetched.policy.issued_at,
                signature=fetched.policy.signature,
                raw_payload=fetched.raw_payload,
            )
        except Exception:
            logger.exception("[runtime] failed to persist verified DevicePolicy cache")
            await self._audit_policy_rejection(
                device_id=config.device.id,
                reason_code="cache_write_failed",
                detail="verified policy applied but cache persistence failed",
                policy_version=fetched.policy.policy_version,
                payload_timestamp=int(fetched.payload.get("timestamp", 0)),
            )

    async def _device_policy_refresh_loop(
        self,
        *,
        config: Config,
        dispatcher: ActionDispatcher,
        refresh_interval_s: float,
    ) -> None:
        """Periodically refresh and apply remote DevicePolicy while runtime is running."""
        interval = max(1.0, float(refresh_interval_s))
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=interval)
                break
            except asyncio.TimeoutError:
                pass  # the refresh interval elapsed: fetch the policy again
            await self._refresh_remote_device_policy_once(
                config=config,
                dispatcher=dispatcher,
                suppress_transient_audit=True,
            )

    def _should_suppress_transient_policy_audit(
        self,
        *,
        reason_code: str,
        detail: str,
    ) -> bool:
        """Deduplicate repeated transient network policy-refresh audit rows."""
        if reason_code not in {"network_error", "network_timeout"}:
            return False
        key = f"{reason_code}:{detail}"
        now = now_ms()
        last = self._last_policy_refresh_transient_audit_ms.get(key)
        if (
            last is not None
            and (now - last) < DEVICE_POLICY_TRANSIENT_AUDIT_SUPPRESS_MS
        ):
            return True
        self._last_policy_refresh_transient_audit_ms[key] = now
        return False

    async def _load_cached_device_policy(
        self,
        config: Config,
        dispatcher: ActionDispatcher,
    ) -> None:
        """Load and verify cached DevicePolicy from SQLite before remote fetch."""
        if self._state_store is None:
            return
        try:
            cached = await self._state_store.get_latest_device_policy_cache()
        except Exception:
            logger.exception("[runtime] failed to read cached DevicePolicy")
            await self._audit_policy_rejection(
                device_id=config.device.id,
                reason_code="cache_read_failed",
                detail="failed to read device_policy_cache row",
                policy_version=None,
                payload_timestamp=None,
            )
            return
        if not cached:
            return

        policy_cfg = (
            config.device_policy if isinstance(config.device_policy, dict) else {}
        )
        public_key_b64 = str(policy_cfg.get("public_key_b64", "")).strip()
        if not public_key_b64:
            logger.warning(
                "[runtime] cached DevicePolicy exists but device_policy.public_key_b64 is not configured"
            )
            await self._audit_policy_rejection(
                device_id=config.device.id,
                reason_code="cache_verification_unavailable",
                detail="missing device_policy.public_key_b64 for cached policy verification",
                policy_version=int(cached.get("policy_version", 0)),
                payload_timestamp=None,
            )
            return

        raw_payload = str(cached.get("raw_payload", "") or "")
        if not raw_payload:
            logger.warning("[runtime] cached DevicePolicy missing raw_payload")
            await self._audit_policy_rejection(
                device_id=config.device.id,
                reason_code="cache_missing_raw_payload",
                detail="device_policy_cache row has empty raw_payload",
                policy_version=int(cached.get("policy_version", 0)),
                payload_timestamp=None,
            )
            return

        try:
            parsed_payload = json.loads(
                raw_payload,
                object_pairs_hook=unique_members(),
            )
            if not isinstance(parsed_payload, dict):
                raise ValueError("cached raw payload is not a JSON object")
            verify_signed_payload(
                parsed_payload,
                public_key_b64,
                context_label="cached device policy payload",
            )
            cached_policy = device_policy_from_payload(
                parsed_payload,
                context_label="cached device policy payload",
            )
        except Exception as exc:
            logger.warning("[runtime] cached DevicePolicy rejected: %s", exc)
            await self._audit_policy_rejection(
                device_id=config.device.id,
                reason_code="cache_invalid_payload",
                detail=str(exc),
                policy_version=int(cached.get("policy_version", 0)),
                payload_timestamp=None,
            )
            return

        dispatcher.update_policy(cached_policy)
        logger.info(
            "[runtime] cached DevicePolicy applied — version=%s tier=%s valid_until=%s",
            cached_policy.policy_version,
            cached_policy.tier,
            cached_policy.valid_until,
        )

    async def _audit_policy_rejection(
        self,
        *,
        device_id: str,
        reason_code: str,
        detail: str,
        policy_version: int | None,
        payload_timestamp: int | None,
    ) -> None:
        if self._state_store is None:
            return
        audit_reason = json.dumps(
            {
                "code": reason_code,
                "detail": detail,
                "policy_version": policy_version,
                "payload_timestamp": payload_timestamp,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        try:
            await self._state_store.log_override(
                trigger_name="device_policy_refresh",
                action="refresh_device_policy",
                reason=audit_reason,
                operator_response=None,
                override_type="policy_rejection",
                device_id=device_id,
            )
        except Exception:
            logger.exception("[runtime] failed to persist policy rejection audit trail")
