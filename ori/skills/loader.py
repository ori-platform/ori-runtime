# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Skill loader — reads skill.yaml directories and wires EventBus handlers.

This module is the loader's interface and holds no code of its own. The loader
runs in private modules beside it, one per concern: ``_manifest`` (the data
model, grammar and workload budgets), ``_provenance`` (which skills ship with
the runtime), ``_validation``, ``_registration`` and ``_loader``
(``SkillLoader``, which composes them over ``_core``). A test that patches the
loader patches the binding its caller reads in those modules;
``tests/package_layout.py`` refuses a patch on a name here.

Usage::

    loader = SkillLoader(elevator, state_store, dispatcher)
    skills = loader.load_selected([("pc-system-health", "")], "/path/to/skills")
    for skill in skills:
        loader.register(skill, event_bus)
"""

from ori.skills._loader import SkillLoader
from ori.skills._manifest import (
    MAX_TOTAL_SUBSCRIPTIONS,
    CommunitySkillAdmission,
    Skill,
    SkillSelectionError,
    SkillValidationError,
    Trigger,
)
from ori.skills._provenance import first_party_skill_roots

__all__ = [
    "MAX_TOTAL_SUBSCRIPTIONS",
    "CommunitySkillAdmission",
    "Skill",
    "SkillLoader",
    "SkillSelectionError",
    "SkillValidationError",
    "Trigger",
    "first_party_skill_roots",
]
