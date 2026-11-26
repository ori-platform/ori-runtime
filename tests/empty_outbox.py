# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A state store holding an empty alert outbox, for health snapshots.

runtime-health/v4 reads an unopened store as `alert_outbox` `starting`, so a
bare runtime that should read healthy needs a store that answers the summary.
"""

from typing import Any


class EmptyOutboxStore:
    async def get_alert_outbox_summary(self) -> dict[str, Any]:
        return {
            "backlog_count": 0,
            "oldest_queued_original_ts": None,
            "oldest_queued_at_ms": None,
            "tier_d_unresolved_count": 0,
            "tier_d_max_attempts": None,
            "tier_d_oldest_queued_at_ms": None,
            "protection_degraded_unresolved_count": 0,
            "protection_degraded_max_attempts": None,
            "protection_degraded_oldest_queued_at_ms": None,
            "oldest_non_tier_d_queued_at_ms": None,
        }
