# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import time
from dataclasses import dataclass


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
        )
