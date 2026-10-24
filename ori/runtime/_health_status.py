# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""How component health folds into one status, and the degradation reasons."""

from ori.gateway.node_heartbeat import DEGRADATION_REASON_FIRMWARE_LIVENESS

_HEALTH_SEVERITY_RANK = {"degraded": 1, "critical": 2}


def fold_health_status(severities: list[str]) -> str | None:
    """The most severe condition that holds, or None when none does.

    An unrecognised severity raises rather than ranking as either.
    """
    return max(severities, key=_HEALTH_SEVERITY_RANK.__getitem__, default=None)


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
