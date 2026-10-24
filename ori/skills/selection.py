# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The runtime's side of ``skills:``: where skills are read, which, and the log."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ori.config import anchor_to_config
from ori.skills.loader import Skill, SkillLoader, SkillSelectionError

logger = logging.getLogger(__name__)


def skills_dir_for(declared: str | None, config_path: str) -> str:
    """The deployment's skills directory, anchored to the configuration.

    A relative value would otherwise resolve against the working directory,
    which the unit points at a runtime directory systemd empties on every stop.
    Skills that vanish take their triggers with them, and a skill can carry
    Tier D coverage.
    """
    return anchor_to_config(
        declared or str(Path(config_path).parent / "skills"), config_path
    )


def load_selection(
    loader: SkillLoader,
    selection: Sequence[tuple[str, str]],
    skills_dir: str,
    *,
    refuse_unresolved: bool,
) -> list[Skill] | None:
    """The listed skills, or None when ``skills:`` cannot be honoured.

    With *refuse_unresolved*, as at startup, the error is raised instead.
    """
    try:
        return loader.load_selected(selection, skills_dir)
    except SkillSelectionError as exc:
        if refuse_unresolved:
            raise
        logger.error(
            "[runtime] skill reload rejected — skills: %s; keeping the existing "
            "handler graph",
            exc,
        )
        return None


def log_tier_configuration(skills: Sequence[Any]) -> None:
    for skill in skills:
        logger.info("[skill] %s v%s loaded", skill.name, skill.version)
        for trigger in skill.triggers:
            escalation = "bypass_llm" if trigger.bypass_llm else trigger.escalate_to
            logger.info(
                "  trigger: %s → Tier %s → %s",
                trigger.name,
                trigger.action_tier,
                escalation,
            )
