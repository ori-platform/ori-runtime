# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Where a split package's code lives, for tests that patch it.

``ori.config`` and ``ori.runtime`` are packages whose ``__init__`` only
re-exports: the code runs in private modules under ``ori/config/`` and
``ori/runtime/``. Patching a name on the package rebinds the re-export and
leaves the module that calls it untouched, so the patch does nothing and a
test built on it checks nothing. A private module imports what it calls by
value, so patch every binding a caller reads, the callers' own bindings among
them, not only the module that defines it: `PackageLayout.owners` lists them
for each re-export, and `runtime_bindings` for any name the runtime's modules
read.

While the suite runs, `hold_reexports` refuses every rebinding of a
re-export and observes every binding a test changes in any module of either
package, however soon the change is undone. The conftest fails a test that
changed a binding no caller reads, or an Ori object's binding in some of the
modules that read it and never in the others; `binding_problems` says which.
Setup, the call and teardown are each judged from the bindings as they find
them, so a fixture's complete patch is where the call starts.
Four limits. A phase is judged on which bindings it changed, not when, so
patching every binding of an object in turn, never all at once, passes; and
a fixture that patches some bindings, with the test body patching the rest,
is refused as partial in setup. A write past a module's class and the
mapping writers, straight into its namespace or through
``types.ModuleType.__setattr__``, is seen only if it is still in place at the
next check. A patch on a stand-in put in ``sys.modules`` for one of the
modules lands on the stand-in, which is no module the guard watches. And a
run that ``pytest.exit`` or an interrupt ends before a phase is reported
loses that phase's findings with its report.
"""

from __future__ import annotations
import __future__

import ast
import contextlib
import functools
import importlib
import inspect
import pkgutil
import sys
import types
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from unittest import mock


class PackageLayout:
    """A package that only re-exports, and the private modules behind it."""

    def __init__(self, name: str, *, min_modules: int, owners_label: str) -> None:
        self.name = name
        self.min_modules = min_modules
        #: What the refusal calls the owner listing, in its advice.
        self.owners_label = owners_label

    @property
    def package(self) -> types.ModuleType:
        return importlib.import_module(self.name)

    def modules(self) -> tuple[types.ModuleType, ...]:
        """Every module under the package, imported here if nothing has yet.

        A module imported on first use, such as ``ori.config.installer``, reads
        its own bindings too, so it is imported up front rather than missed.
        """
        for found in pkgutil.iter_modules(self.package.__path__):
            importlib.import_module(f"{self.name}.{found.name}")
        return tuple(
            value
            for value in vars(self.package).values()
            if isinstance(value, types.ModuleType)
            and value.__name__.startswith(f"{self.name}.")
        )

    def bindings_of(self, value: object) -> tuple[str, ...]:
        """Every binding of *value* in the package's modules, as dotted targets.

        A private module imports what it calls by value, under its own local
        name, so the binding a caller looks up is in the caller's module:
        ``Config.load`` reads ``ori.config._config.parse_actions``, not the
        binding in ``ori.config._actions`` where the function is defined.
        Patching takes effect only on the bindings callers read, so all of them
        are listed, the defining module's included.
        """
        return tuple(
            sorted(
                f"{module.__name__}.{local}"
                for module in self.modules()
                for local, bound in vars(module).items()
                if bound is value and not local.startswith("__")
            )
        )

    @functools.cache
    def owners(self) -> dict[str, tuple[str, ...]]:
        """Each name the package exports -> every binding a caller of it reads."""
        assert len(self.modules()) > self.min_modules, (
            f"found too few modules under {self.name.replace('.', '/')}/"
        )
        package = self.package
        return {
            name: self.bindings_of(getattr(package, name)) for name in package.__all__
        }

    def refusal(self, name: str) -> str:
        where = ", ".join(self.owners().get(name, ())) or "the binding its caller reads"
        return (
            f"{self.name}.{name} is a re-export; rebinding it reaches no "
            f"caller. Patch each binding a caller reads instead: {where}."
        )

    def absent_refusal(self, name: str) -> str:
        return (
            f"{self.name} does not bind {name}, so binding it reaches no caller. "
            "Patch each binding a caller reads, in the modules under "
            f"{self.name.replace('.', '/')}/."
        )

    def shared_bindings(self) -> list[tuple[str, ...]]:
        """Groups of bindings that name one Ori object in more than one module.

        A function, class or module is grouped by identity, whatever local name
        each module gives it; any other value, a logger or a constant, only
        with others of its name, because equal numbers can be one object. A
        module, function or class from outside Ori, ``os`` or ``Path``, is
        each module's own tool: patching one module's binding of it fakes that
        module alone.
        """
        groups: dict[object, list[str]] = {}
        for module in self.modules():
            for local, value in vars(module).items():
                if local.startswith("__"):
                    continue
                shareable = isinstance(value, (types.ModuleType, type)) or callable(
                    value
                )
                if shareable and not _is_ori(value):
                    continue
                if isinstance(value, __future__._Feature):  # type: ignore[attr-defined]
                    continue  # a compiler flag such as ``annotations``
                key: object = id(value) if shareable else (local, id(value))
                groups.setdefault(key, []).append(f"{module.__name__}.{local}")
        return [tuple(sorted(found)) for found in groups.values() if len(found) > 1]

    def namespace_refusal(self) -> str:
        return (
            f"{self.name}'s namespace holds re-exports; writing it reaches "
            f"no caller. Patch each binding a caller reads, as {self.owners_label} "
            "lists them, instead."
        )

    def bindings(self) -> dict[str, int]:
        """The object each re-export is bound to now, by identity."""
        namespace = vars(self.package)
        return {
            name: id(namespace[name]) for name in self.owners() if name in namespace
        }

    def rebound(self, before: dict[str, int]) -> list[str]:
        """Refusals for re-exports bound to another object than *before*, or gone."""
        now = self.bindings()
        return [
            self.refusal(name)
            for name, ident in before.items()
            if now.get(name) != ident
        ]


CONFIG = PackageLayout("ori.config", min_modules=10, owners_label="config_owners")
RUNTIME = PackageLayout("ori.runtime", min_modules=20, owners_label="runtime_owners")
LAYOUTS: tuple[PackageLayout, ...] = (CONFIG, RUNTIME)
_BY_NAME = {layout.name: layout for layout in LAYOUTS}


# ── ori.config ────────────────────────────────────────────────────────────────


def section_modules() -> tuple[types.ModuleType, ...]:
    """The private modules under ``ori/config/`` the package re-exports from."""
    return CONFIG.modules()


def bindings_of(value: object) -> tuple[str, ...]:
    """Every ``ori/config/`` binding of *value*, as dotted targets."""
    return CONFIG.bindings_of(value)


def config_owners() -> dict[str, tuple[str, ...]]:
    """Each name ``ori.config`` exports -> every binding a caller of it reads."""
    return CONFIG.owners()


# ── ori.runtime ───────────────────────────────────────────────────────────────


def runtime_owners() -> dict[str, tuple[str, ...]]:
    """Each name ``ori.runtime`` exports -> every binding a caller of it reads."""
    return RUNTIME.owners()


def runtime_bindings(name: str) -> tuple[str, ...]:
    """Every binding under ``ori/runtime/`` a reader of *name* looks up.

    *name* is the name the runtime's modules import a value under. A function,
    class or module is found by identity, so a binding under another local
    name is listed too; any other value, such as a number, only under *name*,
    because equal numbers can be one object and an unrelated constant would be
    patched with it. Every module binding *name* must bind the same object.
    """
    found = {
        module.__name__: vars(module)[name]
        for module in RUNTIME.modules()
        if name in vars(module)
    }
    assert found, f"no module under ori/runtime/ binds {name}"
    values = {id(value) for value in found.values()}
    assert len(values) == 1, f"ori/runtime/ binds {name} to different objects"
    value = next(iter(found.values()))
    if isinstance(value, (types.FunctionType, type, types.ModuleType)):
        return RUNTIME.bindings_of(value)
    return tuple(sorted(f"{module}.{name}" for module in found))


def patch_runtime(monkeypatch: Any, name: str, value: object) -> None:
    """``monkeypatch.setattr`` every binding a runtime reader of *name* looks up."""
    for target in runtime_bindings(name):
        monkeypatch.setattr(target, value)


@contextlib.contextmanager
def patched_runtime(name: str, new: Any = mock.DEFAULT, **kwargs: Any) -> Iterator[Any]:
    """``mock.patch`` every binding of *name* under ``ori/runtime/`` with one object.

    Yields what ``mock.patch`` yields for the first binding: the mock it made
    from *kwargs*, or *new*.
    """
    first, *rest = runtime_bindings(name)
    with contextlib.ExitStack() as stack:
        patched = stack.enter_context(mock.patch(first, new, **kwargs))
        for target in rest:
            stack.enter_context(mock.patch(target, patched))
        yield patched


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DIR = ROOT / "ori" / "runtime"


def runtime_source_paths() -> tuple[Path, ...]:
    """Every module of the runtime package, which replaced ``ori/runtime.py``."""
    paths = tuple(sorted(RUNTIME_DIR.glob("*.py")))
    assert len(paths) > RUNTIME.min_modules, paths
    return paths


def runtime_source() -> str:
    """Every runtime module's text, in path order, for a guard that read the file."""
    return "\n".join(
        path.read_text(encoding="utf-8") for path in runtime_source_paths()
    )


def runtime_tree() -> ast.Module:
    """One syntax tree holding every runtime module's statements, in path order.

    For a guard that walked ``ori/runtime.py`` whole: walking this sees the same
    statements, wherever the split put them. Line numbers repeat across
    modules, so a guard that reports a location reads `runtime_source_paths`.
    """
    body: list[ast.stmt] = []
    for path in runtime_source_paths():
        body += ast.parse(path.read_text(encoding="utf-8")).body
    return ast.Module(body=body, type_ignores=[])


def runtime_methods() -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    """Each method ``OriRuntime`` has, parsed from the class that defines it.

    ``OriRuntime`` is composed from one class per domain; this reads every
    class in its method resolution order, so a method is found wherever it
    lives. A name defined twice would shadow, and is refused.
    """
    from ori.runtime import OriRuntime

    found: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for cls in OriRuntime.__mro__[:-1]:
        source = inspect.getsourcefile(cls)
        assert source is not None, cls
        tree = ast.parse(Path(source).read_text(encoding="utf-8"))
        (node,) = [
            n
            for n in tree.body
            if isinstance(n, ast.ClassDef) and n.name == cls.__name__
        ]
        for item in node.body:
            if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
                assert item.name not in found, f"{item.name} is defined twice"
                found[item.name] = item
    assert len(found) > 100, "found too few OriRuntime methods"
    return found


# ── The guard ─────────────────────────────────────────────────────────────────


class ReexportRebindError(AttributeError):
    """A test tried to rebind or delete a name a split package re-exports."""


def _is_ori(value: object) -> bool:
    """Whether a module, function or class is Ori's own."""
    while isinstance(value, functools.partial):
        value = value.func
    name = (
        value.__name__
        if isinstance(value, types.ModuleType)
        else getattr(value, "__module__", None)
    )
    return isinstance(name, str) and (name == "ori" or name.startswith("ori."))


def _is_own_submodule(package: types.ModuleType, name: str, value: object) -> bool:
    """The import system binding a submodule on its package, on first import."""
    return isinstance(value, types.ModuleType) and value is sys.modules.get(
        f"{package.__name__}.{name}"
    )


class _BindingsWatched(types.ModuleType):
    """A module of a split package while the suite runs: every attribute write
    to it is observed, from ``monkeypatch.setattr`` and ``mock.patch`` to plain
    assignment and ``delattr``, however briefly it lasts."""

    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        _observe(self, name)

    def __delattr__(self, name: str) -> None:
        super().__delattr__(name)
        _observe(self, name)


class _ReexportsHeld(_BindingsWatched):
    """A split package while the suite runs: a re-export cannot be rebound.

    Binding the same object again, or a name the package does not re-export,
    such as a private module the import system binds on first import, is
    allowed.
    """

    def __setattr__(self, name: str, value: object) -> None:
        layout = _BY_NAME[self.__name__]
        if name in layout.owners() and vars(self).get(name) is not value:
            raise ReexportRebindError(layout.refusal(name))
        if name not in vars(self) and not _is_own_submodule(self, name, value):
            # A name the package never bound reaches no caller either: it is
            # what ``raising=False`` or ``create=True`` makes of a stale target.
            raise ReexportRebindError(layout.absent_refusal(name))
        super().__setattr__(name, value)

    def __delattr__(self, name: str) -> None:
        layout = _BY_NAME[self.__name__]
        if name in layout.owners():
            raise ReexportRebindError(layout.refusal(name))
        super().__delattr__(name)


#: What `hold_reexports` replaced, restored by `release_reexports`.
_HELD: dict[str, Any] = {}


def _held_layout(mapping: object) -> PackageLayout | None:
    for layout in LAYOUTS:
        if mapping is vars(layout.package):
            return layout
    return None


def _hold_namespace_writers() -> None:
    """Refuse the mapping writers aimed at a split package's namespace.

    ``mock.patch.dict`` and ``MonkeyPatch``'s ``setitem`` and ``delitem``
    change the mapping directly, past the module's class, and a ``with`` block
    restores it before the test ends. Each is refused when the mapping it
    targets is a held namespace itself, whatever the target's spelling; any
    other mapping passes, including a view such as ``ChainMap`` that delegates
    to the namespace, which this does not recognise.
    """
    from _pytest.monkeypatch import MonkeyPatch

    patch_dict_class: Any = mock._patch_dict  # type: ignore[attr-defined]
    apply = patch_dict_class._patch_dict
    unapply = patch_dict_class._unpatch_dict
    setitem = MonkeyPatch.setitem
    delitem = MonkeyPatch.delitem
    _HELD.update(apply=apply, setitem=setitem, delitem=delitem)

    def patch_dict(self: Any) -> Any:
        result = apply(self)  # resolves a string target to its mapping first
        layout = _held_layout(self.in_dict)
        if layout is not None:
            unapply(self)  # the refused write, undone before it is checked
            raise AssertionError(layout.namespace_refusal())
        _observe_mapping(self.in_dict)
        return result

    def guarded_setitem(self: MonkeyPatch, dic: Any, name: Any, value: Any) -> None:
        layout = _held_layout(dic)
        if layout is not None:
            raise AssertionError(layout.namespace_refusal())
        setitem(self, dic, name, value)
        _observe_mapping(dic)

    def guarded_delitem(
        self: MonkeyPatch, dic: Any, name: Any, raising: bool = True
    ) -> None:
        layout = _held_layout(dic)
        if layout is not None:
            raise AssertionError(layout.namespace_refusal())
        delitem(self, dic, name, raising)
        _observe_mapping(dic)

    patch_dict_class._patch_dict = patch_dict
    MonkeyPatch.setitem = guarded_setitem  # type: ignore[method-assign]
    MonkeyPatch.delitem = guarded_delitem  # type: ignore[method-assign]


def hold_reexports() -> None:
    """Refuse every rebinding of a split package's re-export for a test session,
    and observe every binding a test changes in any of its modules.

    Attribute spellings go through each module's class; ``patch.dict``,
    ``setitem`` and ``delitem`` are refused on a package's namespace and
    observed on a private module's. A plain dict operation on a namespace that
    the same test undoes before a check is outside both. Installing twice is a
    no-op, and `release_reexports` restores what this replaced.
    """
    if _HELD:
        return
    for layout in LAYOUTS:
        layout.owners()  # computed before the class swap, from the real bindings
    held = [
        module for layout in LAYOUTS for module in (layout.package, *layout.modules())
    ]
    _HELD["module_classes"] = {module.__name__: type(module) for module in held}
    for module in held:
        # A module's class may be swapped for a ModuleType subclass; pyright
        # does not model that, so the assignment goes through Any.
        cast(Any, module).__class__ = (
            _ReexportsHeld if module.__name__ in _BY_NAME else _BindingsWatched
        )
    _hold_namespace_writers()
    _HELD["snapshot"] = take_snapshot()


def release_reexports() -> None:
    """Restore what `hold_reexports` replaced, when the test session ends."""
    if not _HELD:
        return
    from _pytest.monkeypatch import MonkeyPatch

    for name, original in _HELD["module_classes"].items():
        # Past the trap, which refuses every name the package never bound.
        types.ModuleType.__setattr__(sys.modules[name], "__class__", original)
    cast(Any, mock)._patch_dict._patch_dict = _HELD["apply"]
    MonkeyPatch.setitem = _HELD["setitem"]  # type: ignore[method-assign]
    MonkeyPatch.delitem = _HELD["delitem"]  # type: ignore[method-assign]
    _HELD.clear()
    _forget()


def bindings() -> dict[str, int]:
    """The object each re-export of every split package is bound to now."""
    return {
        f"{layout.name}.{name}": ident
        for layout in LAYOUTS
        for name, ident in layout.bindings().items()
    }


def rebound(before: dict[str, int]) -> list[str]:
    """Refusals for re-exports bound to another object than *before*, or gone.

    Catches what the class cannot: a write straight into a package's
    ``__dict__``, as ``monkeypatch.setitem(vars(ori.config), ...)`` makes.
    """
    problems = []
    for layout in LAYOUTS:
        prefix = f"{layout.name}."
        mine = {
            key.removeprefix(prefix): ident
            for key, ident in before.items()
            if key.startswith(prefix) and "." not in key.removeprefix(prefix)
        }
        problems += layout.rebound(mine)
    return problems


# ── What a test leaves bound ──────────────────────────────────────────────────


@dataclass(frozen=True)
class BindingSnapshot:
    """Every binding in every module of every split package, by identity."""

    #: Each module's bindings, the objects themselves: an id alone could be
    #: reused by a new object once a test let the original go.
    modules: dict[str, dict[str, object]]
    #: Bindings of one object in more than one module, from `shared_bindings`.
    groups: tuple[tuple[str, ...], ...]
    #: The names each module bound when the session began, which a phase's
    #: own starting point does not change.
    names: dict[str, frozenset[str]]


def _namespace(module: types.ModuleType) -> dict[str, object]:
    return {
        name: value for name, value in vars(module).items() if not name.startswith("__")
    }


def take_snapshot() -> BindingSnapshot:
    modules: dict[str, dict[str, object]] = {}
    for layout in LAYOUTS:
        for module in (layout.package, *layout.modules()):
            modules[module.__name__] = _namespace(module)
    return BindingSnapshot(
        modules,
        tuple(group for layout in LAYOUTS for group in layout.shared_bindings()),
        {name: frozenset(bound) for name, bound in modules.items()},
    )


#: What a binding a test deleted resolves to.
_DELETED = object()

#: What the current test changed: every binding it rebound or deleted at any
#: moment, the ones among them that reached no caller while they held, and the
#: problems already reported.
_WATCH: dict[str, set[str]] = {"touched": set(), "stray": set(), "reported": set()}


def _forget() -> None:
    for seen in _WATCH.values():
        seen.clear()


def _observe(module: types.ModuleType, name: str) -> None:
    snapshot: BindingSnapshot | None = _HELD.get("snapshot")
    if snapshot is None or name.startswith("__"):
        return
    before = snapshot.modules.get(module.__name__)
    value = vars(module).get(name, _DELETED)
    if before is None or before.get(name, _DELETED) is value:
        return
    target = f"{module.__name__}.{name}"
    _WATCH["touched"].add(target)
    if value is _DELETED:
        return
    if target in snapshot.modules:
        # A package's binding of its own submodule: only the module itself is
        # one, as the import system binds it on a first import.
        if value is not sys.modules.get(target):
            _WATCH["stray"].add(target)
    elif name not in snapshot.names[module.__name__] and not (
        module.__name__ in _BY_NAME and _is_own_submodule(module, name, value)
    ):
        _WATCH["stray"].add(target)


def _observe_mapping(mapping: object) -> None:
    """Observe a write made to a module's namespace directly, past its class."""
    for module_name in _HELD.get("snapshot", BindingSnapshot({}, (), {})).modules:
        module = sys.modules.get(module_name)
        if module is not None and vars(module) is mapping:
            _observe_module(module)


def _observe_module(module: types.ModuleType) -> None:
    before = _HELD["snapshot"].modules[module.__name__]
    for name in before.keys() | _namespace(module).keys():
        _observe(module, name)


def _consistent(snapshot: BindingSnapshot, group: tuple[str, ...]) -> bool:
    found = set()
    for target in group:
        module, _, name = target.rpartition(".")
        found.add(id(snapshot.modules[module].get(name, _DELETED)))
    return len(found) == 1


def binding_problems(snapshot: BindingSnapshot) -> list[str]:
    """What the current test bound that reached no caller, or only some.

    A binding counts from the moment it changes, however soon it is restored:
    a name a module never bound, which ``raising=False``, ``create=True`` or a
    write to the namespace makes of a stale target; a package's binding of its
    own submodule replaced; a re-export rebound; and an object bound in
    several modules that the test changed in some of them and never in the
    others. A test that patches every binding of an object passes, in whatever
    order it patches and restores them: what this refuses is a list of
    targets missing a caller, not a sequence.
    """
    touched, stray = _WATCH["touched"], _WATCH["stray"]
    problems: list[str] = []
    for target in sorted(stray):
        module_name, _, name = target.rpartition(".")
        if target in snapshot.modules:
            problems.append(
                f"{target} was rebound on its package; no caller reads that "
                "binding. Patch each binding a caller reads, in the module."
            )
            continue
        package = (
            module_name if module_name in _BY_NAME else module_name.rpartition(".")[0]
        )
        problems.append(
            f"{module_name} never bound {name}, so binding it reaches no "
            "caller. Patch each binding a caller reads, in the modules under "
            f"{package.replace('.', '/')}/."
        )
    for layout in LAYOUTS:
        problems += [
            layout.refusal(name)
            for name in layout.owners()
            if f"{layout.name}.{name}" in touched
        ]
    for group in snapshot.groups:
        if not _consistent(snapshot, group):
            # Already split when the phase began: reported then, as a leftover.
            continue
        patched = [target for target in group if target in touched]
        if patched and len(patched) < len(group):
            missed = [target for target in group if target not in touched]
            problems.append(
                f"patched or deleted {', '.join(patched)} but not "
                f"{', '.join(missed)}; "
                "each is read by the code in its own module, so patch them all."
            )
    return problems


def check_bindings() -> list[str]:
    """What the current test changed so far that reaches no caller, or only
    some, not already reported."""
    snapshot: BindingSnapshot | None = _HELD.get("snapshot")
    if snapshot is None:
        return []
    for module_name in snapshot.modules:
        module = sys.modules.get(module_name)
        if module is not None:
            _observe_module(module)
    found = [p for p in binding_problems(snapshot) if p not in _WATCH["reported"]]
    _WATCH["reported"].update(found)
    return found


def take_problems() -> list[str]:
    """Check now, then forget what the test changed: for a test of the guard,
    which makes a refused patch on purpose and reads the refusal itself."""
    found = check_bindings()
    _forget()
    return found


def begin_phase(where: str) -> list[str]:
    """Report what changed since the last check, then judge from here on.

    Setup, the call and teardown are each judged from the bindings as their
    phase finds them, so a complete patch a fixture holds, or an earlier test
    left, is where the call starts: patching one of its bindings in the body
    is partial, however soon it is undone. Which modules bind one object stays
    what the package itself does.
    """
    found = [f"{where}: {problem}" for problem in take_problems()]
    snapshot: BindingSnapshot | None = _HELD.get("snapshot")
    if snapshot is not None:
        _HELD["snapshot"] = BindingSnapshot(
            {
                name: _namespace(module) if module is not None else before
                for name, before in snapshot.modules.items()
                for module in [sys.modules.get(name)]
            },
            snapshot.groups,
            snapshot.names,
        )
    return found
