# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A governed Tier C approval between its commit and the act.

The two refusals that close an approval before it is dispatched, the marker
that lands beside the act, and the settlement of an approval whose workflow
failed before the executor was invoked: tier-c-approval/v1's
`dispatch_not_proven`, reached live under `state_reason` `workflow_failed`
rather than waiting for a restart.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any

from ori.network.events import ActionResult
from ori.reasoning.action_taken import UNRECORDED_SUFFIX
from ori.reasoning.elevator import SkillContext
from ori.reasoning.tier_c_admission import (
    APPROVAL_EXPIRED_UNDISPATCHED,
    APPROVED_PENDING_DISPATCH,
    DISPATCH_NOT_PROVEN,
    DISPATCH_REFUSED_CONTENTION,
    DISPATCH_STARTED,
    UNCERTAIN_STATES,
)

# The dispatcher's own logger: these lines are its, moved here for room.
logger = logging.getLogger("ori.reasoning.action_dispatcher")

Resolved = Callable[..., ActionResult]


def _notify(d: Any, proposal_id: str, *args: Any) -> None:
    """The operator notice, which never undoes the act or refusal it reports."""
    try:
        d._governed_notify(*args)
    except Exception:
        logger.exception(
            "ActionDispatcher: the notice for proposal %s could not be sent",
            proposal_id,
        )


async def refuse_before_act(
    d: Any,
    action: str,
    context: SkillContext,
    store: Any,
    row: dict[str, Any],
    gate_token: Any,
    deadline: float,
    resolved: Resolved,
) -> ActionResult | None:
    """The result of an approval closed before dispatch, or None to dispatch."""
    proposal_id = str(row["proposal_id"])
    safe_default_action = str(row["safe_default_action"])
    if d._clock() > deadline:
        logger.critical(
            "ActionDispatcher: approved proposal %s expired before dispatch; not "
            "carried out, a fresh proposal is required",
            proposal_id,
        )
        recorded = await d._close_now(
            store,
            proposal_id,
            APPROVAL_EXPIRED_UNDISPATCHED,
            from_states=(APPROVED_PENDING_DISPATCH,),
            reason="expired",
            safe_default_action=safe_default_action,
        )
        safe = await d._safe_default_intent(
            store, proposal_id, safe_default_action, context, reason="expired"
        )
        _notify(
            d,
            proposal_id,
            action,
            context,
            f"approval {proposal_id} not carried out: expired",
        )
        return resolved(
            False,
            APPROVAL_EXPIRED_UNDISPATCHED
            if recorded
            else f"{APPROVAL_EXPIRED_UNDISPATCHED}{UNRECORDED_SUFFIX}",
            bool(safe is not None and safe.executed),
            _stamp(safe),
        )
    if (
        gate_token is not None
        and d._resource_gate is not None
        and not await d._resource_gate.reply_admitted(gate_token)
    ):
        logger.critical(
            "ActionDispatcher: approved proposal %s refused at dispatch — an "
            "opposing act holds its resource; not carried out",
            proposal_id,
        )
        recorded = await d._close_now(
            store,
            proposal_id,
            DISPATCH_REFUSED_CONTENTION,
            from_states=(APPROVED_PENDING_DISPATCH,),
            reason="resource_held",
            safe_default_action=safe_default_action,
        )
        safe = await d._safe_default_intent(
            store, proposal_id, safe_default_action, context, reason="contention"
        )
        _notify(
            d,
            proposal_id,
            action,
            context,
            f"approval {proposal_id} not carried out: the resource is held; "
            "a fresh evaluation is required",
        )
        return resolved(
            False,
            DISPATCH_REFUSED_CONTENTION
            if recorded
            else f"{DISPATCH_REFUSED_CONTENTION}{UNRECORDED_SUFFIX}",
            bool(safe is not None and safe.executed),
            _stamp(safe),
        )
    return None


def _stamp(safe: ActionResult | None) -> int | None:
    """A completed safe default's own time, so its result takes no later read."""
    return safe.timestamp if safe is not None else None


def schedule_dispatch_marker(d: Any, store: Any, proposal_id: str) -> None:
    """Mark the approval `dispatch_started` beside the act, never ahead of it."""
    d._pending_outcomes[proposal_id] = time.monotonic()
    if store is not None and hasattr(store, "advance_tier_c_proposal"):

        async def mark() -> None:
            try:
                await store.advance_tier_c_proposal(
                    proposal_id,
                    DISPATCH_STARTED,
                    from_states=(APPROVED_PENDING_DISPATCH,),
                )
            except Exception:
                logger.exception(
                    "ActionDispatcher: dispatch of proposal %s began and could not "
                    "be marked; a restart before its outcome lands records it "
                    "dispatch_not_proven rather than replaying it",
                    proposal_id,
                )

        d._track_tier_d_task(
            asyncio.get_running_loop().create_task(mark(), name="dispatch-started")
        )


async def settle_undispatched(
    d: Any,
    action: str,
    context: SkillContext,
    store: Any,
    row: dict[str, Any],
    resolved: Resolved,
) -> ActionResult:
    """Settle an approval whose workflow failed before the executor was invoked.

    The move to `dispatch_not_proven` is conditional on the row still being
    `approved_pending_dispatch`; the live result names that state only once the
    move is confirmed, and otherwise the state read back, or unrecorded when
    neither can be established. A raised write is never read as a rollback.
    The operator is told in every case.
    """
    proposal_id = str(row["proposal_id"])
    d._pending_outcomes.pop(proposal_id, None)
    moved: bool | None = None
    try:
        moved = bool(
            await store.advance_tier_c_proposal(
                proposal_id,
                DISPATCH_NOT_PROVEN,
                from_states=(APPROVED_PENDING_DISPATCH,),
                reason="workflow_failed",
            )
        )
    except Exception:
        logger.exception(
            "ActionDispatcher: approved proposal %s could not be settled after its "
            "workflow failed; a restart settles it",
            proposal_id,
        )
    state: str | None = DISPATCH_NOT_PROVEN if moved else None
    if not moved:
        try:
            held = await store.get_tier_c_proposal(proposal_id)
            state = str(held["decision_state"]) if held else None
        except Exception:
            state = None
    if state in UNCERTAIN_STATES:
        d._uncertain[proposal_id] = state
    taken = state if state is not None else f"{DISPATCH_NOT_PROVEN}{UNRECORDED_SUFFIX}"
    # Only an uncertain or unknown row holds the outcome until reconciled; a
    # refusal that had already closed the row before the failure does not.
    held = state is None or state in UNCERTAIN_STATES
    blocked = (
        f"; {row.get('outcome')} on zone {row.get('zone_id')} is blocked until an "
        "operator reconciles it"
        if held
        else ""
    )
    logger.critical(
        "ActionDispatcher: approved proposal %s (%s) failed before dispatch; never "
        "replayed, and the row holds %s%s",
        proposal_id,
        action,
        taken,
        blocked,
    )
    _notify(
        d,
        proposal_id,
        action,
        context,
        f"approval {proposal_id} was not carried out: its workflow failed before "
        f"dispatch ({taken.replace('_', ' ')}){blocked}",
    )
    return resolved(False, taken, False)


async def kept_after(
    d: Any, store: Any, row: dict[str, Any], exc: Exception, acted: ActionResult | None
) -> ActionResult:
    """Close a still-open proposal, then keep a dispatch result already obtained.

    Without one, *exc* propagates; a failed close never replaces it.
    """
    proposal_id = str(row["proposal_id"])
    try:
        await d._abort_open_proposal(store, row, reason="workflow_failed")
    except Exception:
        logger.exception(
            "ActionDispatcher: proposal %s could not be closed after its workflow "
            "failed",
            proposal_id,
        )
    if acted is None:
        raise exc
    logger.exception(
        "ActionDispatcher: governed workflow for proposal %s failed after its "
        "dispatch result was obtained; the result is kept",
        proposal_id,
        exc_info=exc,
    )
    return acted
