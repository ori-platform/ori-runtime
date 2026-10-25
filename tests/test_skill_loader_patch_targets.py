# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A test patches every binding the loader's code reads, never ``ori.skills.loader``.

``ori.skills.loader`` only re-exports. The loader runs in private modules beside
it, each of which imports what it calls by value, so a name such as
``first_party_skill_roots`` is read through a binding in every module that uses
it. A patch on the re-export reaches none of them, and a patch on one module
reaches only the code defined there. ``tests/package_layout.py`` refuses every
rebinding of a re-export while the suite runs, and ``skill_loader_bindings``
lists the bindings a patch must reach. These tests drive both.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest import mock

import pytest

import ori.skills.loader
from tests.package_layout import (
    SKILL_LOADER_SIBLINGS,
    ReexportRebindError,
    bindings,
    patch_skill_loader,
    rebound,
    skill_loader_bindings,
    skill_loader_owners,
)

REFUSED = "is a re-export; rebinding it reaches no caller"
SHIPPED = Path(__file__).resolve().parents[1] / "skills"


def test_the_guard_is_installed() -> None:
    assert type(ori.skills.loader).__name__ == "_ReexportsHeld"


def test_every_export_has_an_owner() -> None:
    owners = skill_loader_owners()
    assert set(owners) == set(ori.skills.loader.__all__)
    for name, where in owners.items():
        assert where, name
        assert all(target.startswith("ori.skills._") for target in where), where


@pytest.mark.parametrize(
    "rebind",
    [
        pytest.param(
            lambda mp: mp.setattr(
                "ori.skills.loader.first_party_skill_roots", lambda: ()
            ),
            id="setattr-string",
        ),
        pytest.param(
            lambda mp: mp.setattr(ori.skills.loader, "MAX_TOTAL_SUBSCRIPTIONS", 1),
            id="setattr-object",
        ),
        pytest.param(
            lambda mp: mock.patch("ori.skills.loader.SkillLoader").start(),
            id="mock-patch",
        ),
    ],
)
def test_every_attribute_spelling_is_refused(
    monkeypatch: pytest.MonkeyPatch, rebind: Any
) -> None:
    before = bindings()
    try:
        with pytest.raises(ReexportRebindError, match=REFUSED) as refused:
            rebind(monkeypatch)
    finally:
        mock.patch.stopall()
    assert "Patch each binding a caller reads instead: ori.skills._" in str(
        refused.value
    )
    assert rebound(before) == []


def test_every_reader_of_the_first_party_roots_is_listed() -> None:
    assert skill_loader_bindings("first_party_skill_roots") == (
        "ori.skills._core.first_party_skill_roots",
        "ori.skills._loader.first_party_skill_roots",
        "ori.skills._provenance.first_party_skill_roots",
    )


def _roots_with_one_skill(tmp_path: Path) -> Path:
    import shutil

    root = tmp_path / "roots"
    shutil.copytree(SHIPPED / "pc-system-health", root / "pc-system-health")
    return root


def test_patching_every_binding_reaches_selection_and_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The advice works: selection resolves from the patched roots, and the
    skill it loads is first-party by them."""
    root = _roots_with_one_skill(tmp_path)
    patch_skill_loader(
        monkeypatch, "first_party_skill_roots", lambda: (root.resolve(),)
    )
    loader = ori.skills.loader.SkillLoader()
    skills = loader.load_selected([("pc-system-health", "")], str(tmp_path / "absent"))
    assert [skill.name for skill in skills] == ["pc-system-health"]
    assert skills[0].first_party
    assert loader._is_core_bundled_skill(root / "pc-system-health")


def test_patching_a_method_on_the_class_is_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._is_core_bundled_skill", lambda *_: True
    )
    assert ori.skills.loader.SkillLoader()._is_core_bundled_skill(Path("/nowhere"))


def test_every_gate_keyed_to_a_path_names_every_loader_module() -> None:
    """A gate that names modules by path holds the moved code only if it names
    each module beside the loader; one added later must be added to each."""
    import re
    import tomllib

    root = Path(__file__).resolve().parents[1]
    modules = ("loader", *SKILL_LOADER_SIBLINGS)
    assert len(modules) > 5, modules
    strict = next(
        set(override["module"])
        for override in tomllib.loads((root / "pyproject.toml").read_text())["tool"][
            "mypy"
        ]["overrides"]
        if override.get("disallow_untyped_defs") is True
    )
    boundaries = (root / "scripts" / "typecheck-boundaries.sh").read_text()
    guard = (root / "scripts" / "guard-capability-matrix.sh").read_text()
    declared = re.search(r"CAPABILITY_PATHS='([^']+)'", guard)
    assert declared is not None, "the guard no longer declares CAPABILITY_PATHS"
    capability = re.compile(declared[1])
    for module in modules:
        assert f"ori.skills.{module}" in strict, module
        assert f"ori/skills/{module}.py" in boundaries, module
        assert capability.search(f"ori/skills/{module}.py"), module


def test_every_private_module_beside_the_loader_is_named_as_the_gates_match() -> None:
    """The gates match `_[a-z0-9_]+`, a PEP 8 module name; a private module named
    otherwise would be inventoried here and missed by them, so it is refused.

    Listed independently of `SKILL_LOADER_SIBLINGS`, which this checks.
    """
    import re

    private = sorted(
        path.stem
        for path in (Path(__file__).resolve().parents[1] / "ori" / "skills").iterdir()
        if path.suffix == ".py"
        and path.name.startswith("_")
        and path.name != "__init__.py"
    )
    assert private, "found no private module beside the loader"
    assert tuple(private) == SKILL_LOADER_SIBLINGS
    misnamed = [name for name in private if not re.fullmatch(r"_[a-z0-9_]+", name)]
    assert misnamed == [], (
        f"private modules beside the loader named outside `_[a-z0-9_]+`: {misnamed}; "
        "rename them, since the capability guard and the other gates match that"
    )
