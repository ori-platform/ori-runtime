# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""No module under ori/ grows past a size a reviewer can hold.

New code that would push a module over the limit goes into a new module. The
modules already over it are held at their current size and may only shrink;
when one does, its ceiling comes down with it, so the room is not spent again.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_MODULE_LINES = 2500

#: Modules over the limit, each at the size it may not exceed.
OVERSIZE_CEILINGS: dict[str, int] = {
    "ori/runtime.py": 7940,
    "ori/reasoning/action_dispatcher.py": 5011,
    "ori/config.py": 3531,
    "ori/installer/linux.py": 3377,
    "ori/security/evidence/ledger.py": 2960,
}


def _module_lines() -> dict[str, int]:
    return {
        path.relative_to(ROOT).as_posix(): len(
            path.read_text(encoding="utf-8").splitlines()
        )
        for path in sorted((ROOT / "ori").rglob("*.py"))
    }


def test_no_module_grows_past_the_limit() -> None:
    sizes = _module_lines()
    assert len(sizes) > 100, "the scan found too few modules to be reading ori/"
    over = {
        path: lines
        for path, lines in sizes.items()
        if lines > MAX_MODULE_LINES and path not in OVERSIZE_CEILINGS
    }
    assert not over, (
        f"modules over {MAX_MODULE_LINES} lines: {over}. Move the new code into a "
        "module of its own rather than raising the limit."
    )


def test_an_oversize_module_never_grows() -> None:
    sizes = _module_lines()
    grown = {
        path: (sizes[path], ceiling)
        for path, ceiling in OVERSIZE_CEILINGS.items()
        if sizes[path] > ceiling
    }
    assert not grown, (
        f"oversize modules grew (lines, ceiling): {grown}. Extract code into a new "
        "module until each is back at or under its ceiling."
    )


def test_each_ceiling_is_the_module_s_current_size() -> None:
    sizes = _module_lines()
    stale = {
        path: (sizes.get(path), ceiling)
        for path, ceiling in OVERSIZE_CEILINGS.items()
        if sizes.get(path, 0) < ceiling
    }
    assert not stale, (
        f"oversize modules shrank or were removed (lines, ceiling): {stale}. Lower "
        "each ceiling to the current size, and drop an entry once the module is "
        f"within {MAX_MODULE_LINES} lines."
    )
    assert all(ceiling > MAX_MODULE_LINES for ceiling in OVERSIZE_CEILINGS.values())
