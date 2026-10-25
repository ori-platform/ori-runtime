# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The state every part of the skill loader shares: ``SkillLoader.__init__``."""

import logging
import os
from pathlib import Path
from typing import Any

from ori.skills._manifest import (
    CommunitySkillAdmission,
)
from ori.skills._provenance import (
    HUB_ROOT_PUBLIC_KEY_B64,
    HUB_TRUST_ANCHOR_ENV,
    UNCONFIGURED_HUB_ANCHOR,
    anchor_fault_of,
    first_party_skill_roots,
)

# Every part of the loader logs as it did before the split, under one name an
# operator's logging configuration may already select.
logger = logging.getLogger("ori.skills.loader")


class LoaderCore:
    """The loader's state and its community admission report."""

    def __init__(
        self,
        elevator: Any = None,
        state_store: Any = None,
        dispatcher: Any = None,
        os_sandbox_config: dict[str, Any] | None = None,
        community_trust_anchor_public_key_b64: str | None = None,
        require_signed: bool = False,
        coordinator: Any = None,
    ) -> None:
        self._elevator = elevator
        self._state_store = state_store
        self._dispatcher = dispatcher
        # When present, every handler funnels one event into a single
        # evaluation of every registered skill. Without it each handler
        # evaluates its own skill and schedules its own reasoning, so "Tier D
        # is attempted first" holds only within a skill.
        self._coordinator = coordinator
        self._os_sandbox_config = (
            dict(os_sandbox_config) if isinstance(os_sandbox_config, dict) else {}
        )
        self._community_trust_anchor_public_key_b64 = (
            str(community_trust_anchor_public_key_b64).strip()
            if isinstance(community_trust_anchor_public_key_b64, str)
            else None
        )
        self._require_signed = bool(require_signed)
        # Running total of handlers this loader has subscribed, so the
        # cumulative budget survives across separate register() calls.
        self._registered_subscriptions = 0
        # What the last load_all() made of the community anchor. Both halves
        # are recorded together so a health report never pairs one load's
        # count with another load's anchor.
        self._admission = self._admission_report(fault=self.community_anchor_fault())

    # ── Public API ────────────────────────────────────────────────────────────

    def community_anchor_fault(self) -> str | None:
        """Why no community skill can be verified here, or ``None`` if one can.

        The anchor is the deployment's, so this is answerable before any skill
        directory is read, and it is the same answer for every one of them.
        """
        anchor = self._resolve_community_trust_anchor()
        if anchor == UNCONFIGURED_HUB_ANCHOR:
            return "community skill verification trust anchor is not configured"
        return anchor_fault_of(anchor, self._community_anchor_source())

    def community_admission(self) -> CommunitySkillAdmission:
        """What the last load made of the community anchor."""
        return self._admission

    def _community_anchor_source(self) -> str:
        return (
            "the community trust anchor given to SkillLoader"
            if self._community_trust_anchor_public_key_b64
            else HUB_TRUST_ANCHOR_ENV
        )

    @staticmethod
    def _admission_report(
        *, fault: str | None, refused: int = 0
    ) -> CommunitySkillAdmission:
        return CommunitySkillAdmission(
            anchor_usable=fault is None,
            anchor_fault=fault,
            refused_skills=refused,
        )

    def _resolve_community_trust_anchor(self) -> str:
        """Resolve trust anchor: constructor override > env var > built-in sentinel."""
        if self._community_trust_anchor_public_key_b64:
            return self._community_trust_anchor_public_key_b64

        env_value = os.getenv(HUB_TRUST_ANCHOR_ENV, "").strip()
        if env_value:
            return env_value

        return HUB_ROOT_PUBLIC_KEY_B64

    def _is_core_bundled_skill(self, skill_dir: Path) -> bool:
        """Return True for first-party skills shipped with the runtime."""
        resolved = skill_dir.resolve()
        for root in first_party_skill_roots():
            try:
                resolved.relative_to(root)
                return True
            except ValueError:
                continue
        return False
