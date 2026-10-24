# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Schedule a filesystem change at a named point in a skill selection's load."""

from pathlib import Path
from typing import Any

from ori.skills.loader import SkillLoader, _is_skill_directory

POINTS = ["inside_resolution", "after_resolution", "before_load"]


def swap_at(monkeypatch, point: str, swap: Any) -> None:
    """Run *swap* at *point* in loading the energy skill.

    ``inside_resolution`` is just after resolution finds the directory and
    before it resolves the path; ``after_resolution`` is once resolution has
    returned; ``before_load`` is just before that skill is read.
    """
    if point == "inside_resolution":
        found = _is_skill_directory

        def found_then_swap(path: Path) -> bool:
            answer = found(path)
            if answer and path.name == "energy-anomaly-detector":
                swap()
            return answer

        monkeypatch.setattr("ori.skills.loader._is_skill_directory", found_then_swap)
    elif point == "after_resolution":
        resolve = SkillLoader._resolve_selection

        def resolve_then_swap(self, selection, root):
            resolved = resolve(self, selection, root)
            swap()
            return resolved

        monkeypatch.setattr(SkillLoader, "_resolve_selection", resolve_then_swap)
    else:
        load = SkillLoader.load_one

        def swap_then_load(self, skill_dir, **kwargs):
            if Path(skill_dir).name == "energy-anomaly-detector":
                swap()
            return load(self, skill_dir, **kwargs)

        monkeypatch.setattr(SkillLoader, "load_one", swap_then_load)
