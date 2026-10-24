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
from typing import Any, cast

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


def _refusal(name: str) -> str:
    where = ", ".join(config_owners().get(name, ())) or "the module that reads it"
    return (
        f"{ori.config.__name__}.{name} is a re-export; rebinding it reaches no "
        f"caller. Patch {where} instead."
    )


class _ReexportsHeld(types.ModuleType):
    """``ori.config`` while the suite runs: a re-export cannot be rebound.

    Every attribute spelling of a patch, from ``monkeypatch.setattr`` and
    ``mock.patch`` to plain assignment and ``delattr``, rebinds through here,
    inside a ``with`` block or a fixture as much as in a test body. Binding the
    same object again, or a name the package does not re-export, such as a
    section module the import system binds on first import, is allowed.
    """

    def __setattr__(self, name: str, value: object) -> None:
        if name in config_owners() and vars(self).get(name) is not value:
            raise AssertionError(_refusal(name))
        super().__setattr__(name, value)

    def __delattr__(self, name: str) -> None:
        if name in config_owners():
            raise AssertionError(_refusal(name))
        super().__delattr__(name)


def hold_reexports() -> None:
    """Refuse every attribute rebinding of an ``ori.config`` re-export."""
    config_owners()  # computed before the class swap, from the real bindings
    # A module's class may be swapped for a ModuleType subclass; pyright
    # does not model that, so the assignment goes through Any.
    cast(Any, ori.config).__class__ = _ReexportsHeld


def bindings() -> dict[str, int]:
    """The object each re-export is bound to now, by identity."""
    namespace = vars(ori.config)
    return {name: id(namespace[name]) for name in config_owners() if name in namespace}


def rebound(before: dict[str, int]) -> list[str]:
    """Refusals for re-exports bound to another object than *before*, or gone.

    Catches what the class cannot: a write straight into the module's
    ``__dict__``, as ``monkeypatch.setitem(vars(ori.config), ...)`` makes.
    """
    now = bindings()
    return [_refusal(name) for name, ident in before.items() if now.get(name) != ident]
