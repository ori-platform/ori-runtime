# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""What a ``skills:`` entry in ori.yaml may not carry, and where each setting lives."""

from __future__ import annotations

from typing import Any

from ori.config_fields import ConfigValidationError

# Deployment keys that look like trigger authority -> the skill.yaml trigger
# key that actually holds it (a test ties each target to the trigger grammar).
TRIGGER_OWNED_SKILL_KEYS: dict[str, str] = {
    "safe_default_action": "safe_default_action",
    "action_tier": "action_tier",
    "requires_approval_for_soft_actions": "requires_approval",
    "approval_timeout_seconds": "approval_timeout_seconds",
}


def refuse_skill_config(cfg: Any, context: str) -> None:
    """A skill entry carries no settings; name where each one actually lives."""
    if isinstance(cfg, dict):
        for key in sorted(str(k) for k in cfg):
            if key in TRIGGER_OWNED_SKILL_KEYS:
                raise ConfigValidationError(
                    f"{context}.config.{key} is not a deployment setting: a "
                    f"skill declares it as `{TRIGGER_OWNED_SKILL_KEYS[key]}` on "
                    "its trigger in skill.yaml, and ori.yaml cannot set it."
                )
            if key == "secondary_contact_number":
                raise ConfigValidationError(
                    f"{context}.config.{key} is read by nothing; the escalation "
                    "contact is actions.secondary_contact."
                )
            raise ConfigValidationError(
                f"{context}.config.{key} is read by nothing; every skill setting "
                "is the skill's own, in its skill.yaml."
            )
    raise ConfigValidationError(
        f"{context}.config is not accepted: a skill entry names the skill and its "
        "version only, and every skill setting is the skill's own, in its "
        "skill.yaml."
    )
