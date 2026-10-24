# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Where the configuration loader's code lives, for tests that patch it.

``ori.config`` is a package whose ``__init__`` only re-exports: every section
parser, and every helper one calls, runs in a private module under
``ori/config/``. Patching a name on ``ori.config`` rebinds the re-export and
leaves the module that calls it untouched, so the patch does nothing and a test
built on it checks nothing. Patch the owning module named here instead.
"""

from __future__ import annotations

import functools
import types

import ori.config


def section_modules() -> tuple[types.ModuleType, ...]:
    """The private modules under ``ori/config/`` the package re-exports from."""
    return tuple(
        value
        for value in vars(ori.config).values()
        if isinstance(value, types.ModuleType)
        and value.__name__.startswith(f"{ori.config.__name__}.")
    )


@functools.cache
def config_owners() -> dict[str, tuple[str, ...]]:
    """Each name ``ori.config`` binds -> the modules where patching it takes effect.

    A function or class defined in a section module is owned by that module,
    from its ``__module__``. Anything else, a constant or a name the package
    imports from elsewhere, is owned by every section module binding the same
    object, since each of those reads its own binding.
    """
    sections = section_modules()
    assert len(sections) > 10, "found too few section modules under ori/config/"
    owners: dict[str, tuple[str, ...]] = {}
    for name, value in vars(ori.config).items():
        if name.startswith("__") or any(value is section for section in sections):
            continue
        home = getattr(value, "__module__", None)
        if isinstance(home, str) and home.startswith(f"{ori.config.__name__}."):
            owners[name] = (home,)
            continue
        owners[name] = tuple(
            sorted(
                section.__name__
                for section in sections
                if name in vars(section) and vars(section)[name] is value
            )
        )
    return owners
