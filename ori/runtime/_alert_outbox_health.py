# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""runtime-health/v4's `alert_outbox` block and the conditions it holds."""

from typing import Any

#: runtime-health/v4 defaults. runtime-config/v2 has no key for either, so the
#: default is the value in force.
TIER_D_AGE_BOUND_MS = 300_000
OVERDUE_BOUND_MS = 3_600_000

#: Each condition the block can hold, at runtime-health/v4's severity.
ALERT_OUTBOX_CONDITIONS = {
    "tier_d_alert_delivery_unconfirmed": "critical",
    "protection_degraded_alert_delivery_unconfirmed": "critical",
    "alert_delivery_overdue": "degraded",
    "subsystem_state_unknown_critical": "critical",
    "subsystem_starting": "degraded",
}

_MANDATORY_KINDS = ("tier_d", "protection_degraded")


def _age(now: int, queued_at_ms: object) -> int | None:
    return None if queued_at_ms is None else max(0, now - int(str(queued_at_ms)))


def alert_outbox_block(
    summary: dict[str, Any] | None,
    *,
    state: str,
    now: int,
    configured: dict[str, Any],
) -> dict[str, Any]:
    """The block in *state*; the store's members only when it is `available`.

    *summary* is the store's outbox summary; *configured* the members present
    in every state (bounds, threshold, retry settings).
    """
    block: dict[str, Any] = {
        "state": state,
        **configured,
        "tier_d_age_bound_ms": TIER_D_AGE_BOUND_MS,
        "overdue_bound_ms": OVERDUE_BOUND_MS,
    }
    if state != "available" or summary is None:
        return block
    oldest_queued_at = summary.get("oldest_queued_at_ms")
    block["backlog_count"] = int(summary.get("backlog_count") or 0)
    block["oldest_queued_original_ts"] = summary.get("oldest_queued_original_ts")
    block["oldest_queued_at_ms"] = oldest_queued_at
    # Queue latency is the store's own interval; the producer's time is
    # reported beside it and never ages it.
    block["oldest_queued_age_ms"] = _age(now, oldest_queued_at)
    for kind in _MANDATORY_KINDS:
        block[f"{kind}_unresolved_count"] = int(
            summary.get(f"{kind}_unresolved_count") or 0
        )
        block[f"{kind}_max_attempts"] = summary.get(f"{kind}_max_attempts")
        block[f"{kind}_oldest_age_ms"] = _age(
            now, summary.get(f"{kind}_oldest_queued_at_ms")
        )
    block["oldest_non_tier_d_age_ms"] = _age(
        now, summary.get("oldest_non_tier_d_queued_at_ms")
    )
    return block


def alert_outbox_conditions(block: dict[str, Any]) -> list[str]:
    """The runtime-health/v4 conditions *block* holds, by name."""
    state = block.get("state")
    if state == "unavailable":
        return ["subsystem_state_unknown_critical"]
    if state == "starting":
        return ["subsystem_starting"]
    held: list[str] = []
    threshold = block.get("tier_d_critical_warning_threshold", 3)
    bound = block.get("tier_d_age_bound_ms", TIER_D_AGE_BOUND_MS)
    for kind in _MANDATORY_KINDS:
        attempts = block.get(f"{kind}_max_attempts")
        age = block.get(f"{kind}_oldest_age_ms")
        if block.get(f"{kind}_unresolved_count", 0) > 0 and (
            (attempts is not None and attempts >= threshold)
            or (age is not None and age >= bound)
        ):
            held.append(f"{kind}_alert_delivery_unconfirmed")
    oldest = block.get("oldest_non_tier_d_age_ms")
    if oldest is not None and oldest >= block.get("overdue_bound_ms", OVERDUE_BOUND_MS):
        held.append("alert_delivery_overdue")
    return held
