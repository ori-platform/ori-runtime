# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The registry operations as the operator socket serves them.

One admitted registry operation is in flight per device; another is refused
`registry_busy` before it reads anything. Phone ingress and Tier C admission
are not registry operations: they wait for the store's writer instead.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Final

from ori.security.approvers.registry import (
    ApproverRegistry,
    ChallengeStateLockedError,
    Outcome,
    RegistryRefusedError,
)

if TYPE_CHECKING:
    from ori.state.store import StateStore

logger = logging.getLogger(__name__)

#: The engine operation each socket operation runs.
OPERATION_FOR: Final = {
    "approver_registry_challenge": "issue",
    "approver_registry_recover": "recover",
    "approver_registry_local_seed": "local_seed",
    "approver_registry_enrol": "enrol",
    "approver_registry_revoke": "revoke",
    "approver_registry_binding": "binding",
}

#: The closed `error.code` list of operator-socket/v3 Approver Registry Operations.
REGISTRY_ERRORS: Final = frozenset(
    {
        "payload_too_large",
        "invalid_arguments",
        "unauthenticated",
        "registry_busy",
        "lan_key_required",
        "channel_unauthenticated",
        "device_binding_mismatch",
        "site_binding_mismatch",
        "recovery_not_available",
        "registry_unavailable",
        "active_authorizer_exists",
        "approver_unknown",
        "challenge_reused",
        "challenge_unavailable",
        "challenge_expired",
        "candidate_changed",
        "challenge_stale",
        "possession_invalid",
        "signature_invalid",
        "approver_revoked",
        "credential_reused",
        "value_tombstoned",
        "duplicate_value",
        "authorizer_unavailable",
        "authorizer_not_preexisting",
        "authorizer_not_approver",
        "phone_pending_for_value",
        "anchor_unavailable",
        "malformed",
        "unknown_signer",
        "superseded_signer",
        "wrong_authority",
        "binding_mismatch",
        "revision_regressed",
        "revision_conflict",
        "unknown_target",
        "runtime_store_unavailable",
        "state_store_locked",
        "cancelled",
    }
)

#: A sender that has not answered by then is abandoned: the answer reports no
#: delivery either way, and the in-flight slot must not wait on a provider.
POSSESSION_SEND_TIMEOUT_S: Final = 10.0

#: Sends a possession code: (channel, canonical E.164 value, exact text).
PossessionSender = Callable[[str, str, str], Awaitable[None]]


def _error(code: str, detail: str) -> dict[str, Any]:
    return {"schema_version": 1, "ok": False, "error": {"code": code, "detail": detail}}


class RegistryService:
    """Serve registry operations against the store, one at a time."""

    def __init__(
        self,
        store: StateStore,
        registry: ApproverRegistry,
        *,
        send_possession: PossessionSender | None = None,
    ) -> None:
        self._store = store
        self._registry = registry
        self._send_possession = send_possession
        self._in_flight = False

    @property
    def registry(self) -> ApproverRegistry:
        return self._registry

    def try_admit(self) -> bool:
        """Take the one in-flight slot, or report another operation holds it."""
        if self._in_flight:
            return False
        self._in_flight = True
        return True

    def release(self) -> None:
        self._in_flight = False

    async def serve(self, request: dict[str, Any]) -> dict[str, Any]:
        """Answer one admitted, well-formed registry request."""
        operation = OPERATION_FOR[request["operation"]]
        try:
            outcome = await self._store.run_approver_operation(
                self._registry, operation, request
            )
        except RegistryRefusedError as refused:
            return _error(refused.code, "nothing was recorded")
        except ChallengeStateLockedError:
            return _error(
                "runtime_store_unavailable",
                "a challenge's used marker could not be recorded; restart the runtime",
            )
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                return _error("state_store_locked", "the state store is held")
            return _error("runtime_store_unavailable", "the state store failed")
        except (sqlite3.Error, OSError):
            return _error("runtime_store_unavailable", "the state store failed")
        await self._deliver(outcome)
        return {"schema_version": 1, "ok": True, "result": outcome.result}

    async def phone_text(
        self, channel: str, sender: str, text: str, *, authenticated: bool
    ) -> Outcome:
        """One text from a phone ingress; serialised with registry admission."""
        return await self._store.run_approver_operation(
            self._registry, "phone_text", channel, sender, text, authenticated
        )

    async def _deliver(self, outcome: Outcome) -> None:
        # After the commit, and never reported: the answer does not say whether
        # the code reached its candidate.
        if outcome.possession_message is None:
            return
        channel, to, text = outcome.possession_message
        if self._send_possession is None:
            logger.warning(
                "[approvers] no sender for a %s possession code; the candidate "
                "cannot complete enrolment",
                channel,
            )
            return
        try:
            await asyncio.wait_for(
                self._send_possession(channel, to, text), POSSESSION_SEND_TIMEOUT_S
            )
        except Exception:
            logger.warning("[approvers] a possession code could not be sent")
