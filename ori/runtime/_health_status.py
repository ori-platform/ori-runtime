# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""How component health folds into one status, and the degradation reasons."""

from typing import Any

from ori.gateway.node_heartbeat import DEGRADATION_REASON_FIRMWARE_LIVENESS

_HEALTH_SEVERITY_RANK = {"degraded": 1, "critical": 2}


def fold_health_status(severities: list[str]) -> str | None:
    """The most severe condition that holds, or None when none does.

    An unrecognised severity raises rather than ranking as either.
    """
    return max(severities, key=_HEALTH_SEVERITY_RANK.__getitem__, default=None)


#: runtime-health/v4 startup deadline: a block still initialising this long
#: after the process started reports `unavailable`, never `starting`.
STARTUP_DEADLINE_S = 300.0


def past_startup_deadline(started_monotonic: float, now_monotonic: float) -> bool:
    """Whether the startup deadline has been reached; reaching it is past it."""
    return now_monotonic - started_monotonic >= STARTUP_DEADLINE_S


def firmware_liveness_severity(block: dict[str, Any]) -> str | None:
    """The most severe condition the `firmware_liveness` block holds, or None.

    A stopped or stalled liveness loop is critical or degraded as the
    scheduler reports, and one that does not say which is critical. Held
    manifests that cannot be listed, or a loop not started by the startup
    deadline, are critical (runtime-health/v4 subsystem_state_unknown_critical);
    a loop still within it is degraded (subsystem_starting); and a device that
    does not declare the signing domains is degraded (firmware_signing_domains_undeclared). None of
    these names a token yet; the last is adopted gateway first.
    """
    severities: list[str] = []
    if block["degraded"]:
        severities.append("critical" if block.get("critical", True) else "degraded")
    if block.get("state") == "unavailable":
        severities.append("critical")
    if block.get("state") == "starting":
        severities.append("degraded")
    if block.get("undeclared_device_ids"):
        severities.append("degraded")
    return fold_health_status(severities)


def degradation_reasons(*, firmware_liveness_degraded: bool) -> list[str]:
    """Named degradation reasons for the node heartbeat.

    Returns an empty list when nothing is degraded; the heartbeat omits the
    field entirely in that case. An empty array on the wire is malformed —
    absent and present-empty are different states, and encoding one as the
    other is the ambiguity the contract exists to remove.

    The vocabulary is owned by ``ori.gateway.node_heartbeat``, the wire
    boundary that enforces it, so a token cannot be named here without also
    being publishable there.
    """
    reasons: list[str] = []
    if firmware_liveness_degraded:
        reasons.append(DEGRADATION_REASON_FIRMWARE_LIVENESS)
    return sorted(set(reasons))
