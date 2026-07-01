# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class DevicePolicy:
    tier: str
    relay_b_enabled: bool  # Tier B relay actions permitted
    relay_c_enabled: bool  # Tier C relay actions permitted
    cloud_llm_enabled: bool  # Gateway/cloud reasoning entitlement permitted
    valid_until: int  # unix seconds (14-day lease from ori-cloud)
    policy_version: int  # monotonically increasing
    issued_at: int
    signature: str  # ed25519:<base64> — verified at load time
    alert_sms_monthly_cap: Optional[int] = None
    alert_whatsapp_monthly_cap: Optional[int] = None

    def permits_action(self, action_tier: str) -> bool:
        if action_tier in ("D", "A"):  # Tier D: Invariant 10. Tier A: always.
            return True
        if self.is_expired:
            return False
        if action_tier == "B":
            return self.relay_b_enabled
        if action_tier == "C":
            return self.relay_c_enabled
        return False

    def permits_external_alert(
        self,
        *,
        channel: str,
        action_tier: str,
        current_month_count: int,
    ) -> bool:
        """Apply commercial alert caps without blocking safety.

        Tier D emergency notification is always allowed. Tier A remains a valid
        action, but paid SMS/WhatsApp transport can be capped by policy so free
        deployments keep basic awareness without unbounded messaging cost.
        """

        if action_tier == "D":
            return True
        cap = self.alert_monthly_cap(channel)
        if cap is None or cap < 0:
            return True
        return int(current_month_count) < cap

    def alert_monthly_cap(self, channel: str) -> Optional[int]:
        normalized = str(channel or "").strip().lower()
        if normalized == "sms":
            return self.alert_sms_monthly_cap
        if normalized == "whatsapp":
            return self.alert_whatsapp_monthly_cap
        return None

    @property
    def is_expired(self) -> bool:
        return int(time.time()) > self.valid_until

    @classmethod
    def unrestricted(cls) -> "DevicePolicy":
        """
        Default policy for self-hosted / no ori-cloud deployments.
        All tiers permitted. Never expires.
        Returns full capability — ori-cloud is optional infrastructure.
        """
        return cls(
            tier="self_hosted",
            relay_b_enabled=True,
            relay_c_enabled=True,
            cloud_llm_enabled=True,
            valid_until=2**63 - 1,
            policy_version=0,
            issued_at=0,
            signature="self_hosted",
            alert_sms_monthly_cap=None,
            alert_whatsapp_monthly_cap=None,
        )
