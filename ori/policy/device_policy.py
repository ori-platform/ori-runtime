# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import time
from dataclasses import dataclass, field
from typing import Optional

from ori.policy.alert_classes import ALERT_CLASSES


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
    alerts: dict[str, bool] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name, cap in (
            ("alert_sms_monthly_cap", self.alert_sms_monthly_cap),
            ("alert_whatsapp_monthly_cap", self.alert_whatsapp_monthly_cap),
        ):
            if cap is not None and cap < -1:
                raise ValueError(f"{field_name} must be null, -1, or non-negative")
        # Only known classes carrying a real boolean survive. An unrecognised
        # key cannot disable anything it does not name, and a non-boolean is
        # not a decision to switch a notice off.
        object.__setattr__(
            self,
            "alerts",
            {
                name: value
                for name, value in (self.alerts or {}).items()
                if name in ALERT_CLASSES and isinstance(value, bool)
            },
        )

    def permits_alert_class(
        self, alert_class: Optional[str], *, action_tier: str = "A"
    ) -> bool:
        """Whether a customer has left this class of notice switched on.

        Tier D is exempt, as it is from the monthly cap: a safety-critical
        notice is not a preference, and suppressing one would also read
        downstream as a Tier D action that failed.

        Absence is enablement everywhere else -- a trigger with no class, a
        policy with no `alerts`, a policy omitting this class, and an expired
        lease. Only an explicit `false` on a live policy silences anything.
        """
        if str(action_tier).upper() == "D":
            return True
        if not alert_class:
            return True
        if self.is_expired:
            return True
        return self.alerts.get(alert_class, True) is not False

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
        if cap is None or cap == -1:
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
