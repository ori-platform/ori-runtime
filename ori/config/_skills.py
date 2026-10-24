# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ``skills`` section."""

from dataclasses import dataclass, field
from typing import Any

from ori.config._fields import (
    MAX_SKILL_NAME_LENGTH,
    SKILL_NAME_RE,
    ConfigValidationError,
)
from ori.config._fields import require_optional_str as _require_optional_str
from ori.config._fields import require_str as _require_str
from ori.config._skill_entry import refuse_skill_config as _refuse_skill_config


@dataclass
class SkillConfig:
    name: str
    version: str
    config: dict = field(default_factory=dict)


_SKILL_ENTRY_KEYS = frozenset({"name", "version"})


def parse_skills(data: Any) -> list[SkillConfig]:
    if not isinstance(data, list):
        raise ConfigValidationError("'skills' must be a list.")

    skills = []
    seen: set[str] = set()
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ConfigValidationError(f"skills[{i}] must be a mapping.")
        name = _require_str(item, "name", f"skills[{i}]")
        if len(name) > MAX_SKILL_NAME_LENGTH or not SKILL_NAME_RE.fullmatch(name):
            raise ConfigValidationError(
                f"skills[{i}].name {name!r} is not a skill name: at most "
                f"{MAX_SKILL_NAME_LENGTH} characters, starting with a letter or "
                "digit and using only letters, digits, dot, underscore and hyphen."
            )
        # Folded: a case-insensitive filesystem resolves both to one directory.
        if name.casefold() in seen:
            raise ConfigValidationError(f"skills[{i}] names {name!r} a second time.")
        seen.add(name.casefold())
        context = f"skills[{i}] ({name})"
        if "config" in item:
            _refuse_skill_config(item["config"], context)
        unknown = sorted(str(key) for key in set(item) - _SKILL_ENTRY_KEYS)
        if unknown:
            raise ConfigValidationError(
                f"{context} carries {unknown}; a skill entry names the skill and "
                "its version only, and no deployment setting replaces a skill's "
                "actions."
            )

        version = _require_optional_str(
            item.get("version"),
            f"skills[{i}].version",
            skill_name=name,
        )
        skills.append(
            SkillConfig(
                name=name,
                version=version,
                config={},
            )
        )
    return skills
