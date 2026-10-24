# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Where the configuration loader's code lives, for tests that patch it.

``ori.config`` is a package whose ``__init__`` only re-exports: every section
parser, and every helper one calls, runs in a private module under
``ori/config/``. Patching a name on ``ori.config`` rebinds the re-export and
leaves the module that calls it untouched, so the patch does nothing and a test
built on it checks nothing. A section module imports what it calls by value,
so patch every binding `config_owners` lists for the name, the callers' own
bindings among them, not only the module that defines it.
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
    """Each name ``ori.config`` binds -> every binding a caller of it reads.

    A section module imports what it calls by value, under its own local name,
    so the binding a caller looks up is in the caller's module, not where the
    object was defined: ``Config.load`` reads ``ori.config._config.parse_actions``
    while ``ori.config._parse_actions`` and ``ori.config._actions.parse_actions``
    name the same function. Patching takes effect only on the bindings callers
    read, so this lists every section-module binding of the same object, the
    defining module's included, as dotted targets.
    """
    sections = section_modules()
    assert len(sections) > 10, "found too few section modules under ori/config/"
    owners: dict[str, tuple[str, ...]] = {}
    for name, value in vars(ori.config).items():
        if name.startswith("__") or any(value is section for section in sections):
            continue
        owners[name] = tuple(
            sorted(
                f"{section.__name__}.{local}"
                for section in sections
                for local, bound in vars(section).items()
                if bound is value and not local.startswith("__")
            )
        )
    return owners


def _refusal(name: str) -> str:
    where = ", ".join(config_owners().get(name, ())) or "the binding its caller reads"
    return (
        f"{ori.config.__name__}.{name} is a re-export; rebinding it reaches no "
        f"caller. Patch each binding a caller reads instead: {where}."
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


def _namespace_refusal() -> str:
    return (
        f"{ori.config.__name__}'s namespace holds re-exports; writing it reaches "
        "no caller. Patch each binding a caller reads, as config_owners lists "
        "them, instead."
    )


def _hold_namespace_writers() -> None:
    """Refuse the mapping writers on ``ori.config``'s namespace, by identity.

    ``mock.patch.dict`` and ``MonkeyPatch.setitem`` write the mapping directly,
    past the module's class, and a ``with`` block restores it before the test
    ends. Whatever the target's spelling, the mapping each one is about to
    write is compared with the namespace itself.
    """
    from unittest import mock

    from _pytest.monkeypatch import MonkeyPatch

    namespace = vars(ori.config)
    apply = mock._patch_dict._patch_dict  # type: ignore[attr-defined]

    def patch_dict(self: Any) -> Any:
        result = apply(self)  # resolves a string target to its mapping first
        if self.in_dict is namespace:
            self._unpatch_dict()
            raise AssertionError(_namespace_refusal())
        return result

    mock._patch_dict._patch_dict = patch_dict  # type: ignore[attr-defined]

    setitem = MonkeyPatch.setitem

    def guarded_setitem(self: MonkeyPatch, dic: Any, name: Any, value: Any) -> None:
        if dic is namespace:
            raise AssertionError(_namespace_refusal())
        setitem(self, dic, name, value)

    MonkeyPatch.setitem = guarded_setitem  # type: ignore[method-assign]


def hold_reexports() -> None:
    """Refuse every rebinding of an ``ori.config`` re-export while tests run.

    Attribute spellings go through the module's class; ``patch.dict`` and
    ``setitem`` are refused by the mapping they write. Writes to the
    namespace by plain dict operations, undone by the same test, are outside
    both; the session and per-test snapshots catch any that persist.
    """
    config_owners()  # computed before the class swap, from the real bindings
    # A module's class may be swapped for a ModuleType subclass; pyright
    # does not model that, so the assignment goes through Any.
    cast(Any, ori.config).__class__ = _ReexportsHeld
    _hold_namespace_writers()


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
