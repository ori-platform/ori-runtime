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


def bindings_of(value: object) -> tuple[str, ...]:
    """Every section-module binding of *value*, as dotted targets.

    A section module imports what it calls by value, under its own local name,
    so the binding a caller looks up is in the caller's module: ``Config.load``
    reads ``ori.config._config.parse_actions``, not the binding in
    ``ori.config._actions`` where the function is defined. Patching takes
    effect only on the bindings callers read, so all of them are listed, the
    defining module's included.
    """
    return tuple(
        sorted(
            f"{section.__name__}.{local}"
            for section in section_modules()
            for local, bound in vars(section).items()
            if bound is value and not local.startswith("__")
        )
    )


@functools.cache
def config_owners() -> dict[str, tuple[str, ...]]:
    """Each name ``ori.config`` exports -> every binding a caller of it reads."""
    sections = section_modules()
    assert len(sections) > 10, "found too few section modules under ori/config/"
    return {name: bindings_of(getattr(ori.config, name)) for name in ori.config.__all__}


def _refusal(name: str) -> str:
    where = ", ".join(config_owners().get(name, ())) or "the binding its caller reads"
    return (
        f"{ori.config.__name__}.{name} is a re-export; rebinding it reaches no "
        f"caller. Patch each binding a caller reads instead: {where}."
    )


class ReexportRebindError(AttributeError):
    """A test tried to rebind or delete a name ``ori.config`` re-exports."""


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
            raise ReexportRebindError(_refusal(name))
        super().__setattr__(name, value)

    def __delattr__(self, name: str) -> None:
        if name in config_owners():
            raise ReexportRebindError(_refusal(name))
        super().__delattr__(name)


def _namespace_refusal() -> str:
    return (
        f"{ori.config.__name__}'s namespace holds re-exports; writing it reaches "
        "no caller. Patch each binding a caller reads, as config_owners lists "
        "them, instead."
    )


#: What `hold_reexports` replaced, restored by `release_reexports`.
_HELD: dict[str, Any] = {}


def _hold_namespace_writers() -> None:
    """Refuse the mapping writers aimed at ``ori.config``'s namespace.

    ``mock.patch.dict`` and ``MonkeyPatch``'s ``setitem`` and ``delitem``
    change the mapping directly, past the module's class, and a ``with`` block
    restores it before the test ends. Each is refused when the mapping it
    targets is the namespace itself, whatever the target's spelling; any other
    mapping passes, including a view such as ``ChainMap`` that delegates to the
    namespace, which this does not recognise.
    """
    from unittest import mock

    from _pytest.monkeypatch import MonkeyPatch

    namespace = vars(ori.config)
    patch_dict_class: Any = mock._patch_dict  # type: ignore[attr-defined]
    apply = patch_dict_class._patch_dict
    setitem = MonkeyPatch.setitem
    delitem = MonkeyPatch.delitem
    _HELD.update(apply=apply, setitem=setitem, delitem=delitem)

    def patch_dict(self: Any) -> Any:
        result = apply(self)  # resolves a string target to its mapping first
        if self.in_dict is namespace:
            self._unpatch_dict()
            raise AssertionError(_namespace_refusal())
        return result

    def guarded_setitem(self: MonkeyPatch, dic: Any, name: Any, value: Any) -> None:
        if dic is namespace:
            raise AssertionError(_namespace_refusal())
        setitem(self, dic, name, value)

    def guarded_delitem(
        self: MonkeyPatch, dic: Any, name: Any, raising: bool = True
    ) -> None:
        if dic is namespace:
            raise AssertionError(_namespace_refusal())
        delitem(self, dic, name, raising)

    patch_dict_class._patch_dict = patch_dict
    MonkeyPatch.setitem = guarded_setitem  # type: ignore[method-assign]
    MonkeyPatch.delitem = guarded_delitem  # type: ignore[method-assign]


def hold_reexports() -> None:
    """Refuse every rebinding of an ``ori.config`` re-export for a test session.

    Attribute spellings go through the module's class; ``patch.dict``,
    ``setitem`` and ``delitem`` are refused by the mapping they target. A
    plain dict operation on the namespace that the same test undoes, and a
    write through a mapping that delegates to it, are outside both; the
    session and per-test snapshots catch any that persist. Installing twice
    is a no-op, and `release_reexports` restores what this replaced.
    """
    if _HELD:
        return
    config_owners()  # computed before the class swap, from the real bindings
    _HELD["module_class"] = type(ori.config)
    # A module's class may be swapped for a ModuleType subclass; pyright
    # does not model that, so the assignment goes through Any.
    cast(Any, ori.config).__class__ = _ReexportsHeld
    _hold_namespace_writers()


def release_reexports() -> None:
    """Restore what `hold_reexports` replaced, when the test session ends."""
    if not _HELD:
        return
    from unittest import mock

    from _pytest.monkeypatch import MonkeyPatch

    cast(Any, ori.config).__class__ = _HELD["module_class"]
    cast(Any, mock)._patch_dict._patch_dict = _HELD["apply"]
    MonkeyPatch.setitem = _HELD["setitem"]  # type: ignore[method-assign]
    MonkeyPatch.delitem = _HELD["delitem"]  # type: ignore[method-assign]
    _HELD.clear()


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
