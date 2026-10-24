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
re-export, and the conftest fails a test that left a binding no caller reads,
or patched an object in some of the modules that bind it: `binding_problems`
checks every module of both packages while the patches are still in place,
as each is undone and when the test returns.
"""

from __future__ import annotations

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
        """Groups of bindings that name one object in more than one module.

        A function, class or module is grouped by identity, whatever local name
        each module gives it; any other value only with others of its name,
        because equal numbers can be one object.
        """
        groups: dict[object, list[str]] = {}
        for module in self.modules():
            for local, value in vars(module).items():
                if local.startswith("__"):
                    continue
                shareable = isinstance(
                    value,
                    (
                        types.FunctionType,
                        types.BuiltinFunctionType,
                        type,
                        types.ModuleType,
                    ),
                ) or callable(value)
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


def _is_own_submodule(package: types.ModuleType, name: str, value: object) -> bool:
    """The import system binding a submodule on its package, on first import."""
    return isinstance(value, types.ModuleType) and value is sys.modules.get(
        f"{package.__name__}.{name}"
    )


class _ReexportsHeld(types.ModuleType):
    """A split package while the suite runs: a re-export cannot be rebound.

    Every attribute spelling of a patch, from ``monkeypatch.setattr`` and
    ``mock.patch`` to plain assignment and ``delattr``, rebinds through here,
    inside a ``with`` block or a fixture as much as in a test body. Binding the
    same object again, or a name the package does not re-export, such as a
    private module the import system binds on first import, is allowed.
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
        _patched()
        return result

    def guarded_setitem(self: MonkeyPatch, dic: Any, name: Any, value: Any) -> None:
        layout = _held_layout(dic)
        if layout is not None:
            raise AssertionError(layout.namespace_refusal())
        setitem(self, dic, name, value)
        _patched()

    def guarded_delitem(
        self: MonkeyPatch, dic: Any, name: Any, raising: bool = True
    ) -> None:
        layout = _held_layout(dic)
        if layout is not None:
            raise AssertionError(layout.namespace_refusal())
        delitem(self, dic, name, raising)
        _patched()

    patch_dict_class._patch_dict = patch_dict
    MonkeyPatch.setitem = guarded_setitem  # type: ignore[method-assign]
    MonkeyPatch.delitem = guarded_delitem  # type: ignore[method-assign]


def hold_reexports() -> None:
    """Refuse every rebinding of a split package's re-export for a test session.

    Attribute spellings go through the module's class; ``patch.dict``,
    ``setitem`` and ``delitem`` are refused by the mapping they target. A
    plain dict operation on the namespace that the same test undoes, and a
    write through a mapping that delegates to it, are outside both; the
    session and per-test snapshots catch any that persist. Installing twice
    is a no-op, and `release_reexports` restores what this replaced.
    """
    if _HELD:
        return
    module_classes: dict[str, type] = {}
    for layout in LAYOUTS:
        layout.owners()  # computed before the class swap, from the real bindings
        module_classes[layout.name] = type(layout.package)
    _HELD["module_classes"] = module_classes
    for layout in LAYOUTS:
        # A module's class may be swapped for a ModuleType subclass; pyright
        # does not model that, so the assignment goes through Any.
        cast(Any, layout.package).__class__ = _ReexportsHeld
    _hold_namespace_writers()
    _watch_patches()
    _HELD["snapshot"] = take_snapshot()


def release_reexports() -> None:
    """Restore what `hold_reexports` replaced, when the test session ends."""
    if not _HELD:
        return
    from _pytest.monkeypatch import MonkeyPatch

    for layout in LAYOUTS:
        # Past the trap, which refuses every name the package never bound.
        types.ModuleType.__setattr__(
            layout.package, "__class__", _HELD["module_classes"][layout.name]
        )
    cast(Any, mock)._patch_dict._patch_dict = _HELD["apply"]
    MonkeyPatch.setitem = _HELD["setitem"]  # type: ignore[method-assign]
    MonkeyPatch.delitem = _HELD["delitem"]  # type: ignore[method-assign]
    for (owner, name), original in _HELD["watched"].items():
        setattr(owner, name, original)
    _HELD.clear()
    _WATCH.update(dirty=False, found=[])


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

    modules: dict[str, dict[str, int]]
    #: Bindings of one object in more than one module, from `shared_bindings`.
    groups: tuple[tuple[str, ...], ...]


def _namespace(module: types.ModuleType) -> dict[str, int]:
    return {
        name: id(value)
        for name, value in vars(module).items()
        if not name.startswith("__")
    }


def take_snapshot() -> BindingSnapshot:
    modules: dict[str, dict[str, int]] = {}
    for layout in LAYOUTS:
        for module in (layout.package, *layout.modules()):
            modules[module.__name__] = _namespace(module)
    return BindingSnapshot(
        modules,
        tuple(group for layout in LAYOUTS for group in layout.shared_bindings()),
    )


def binding_problems(snapshot: BindingSnapshot) -> list[str]:
    """What a test bound that reaches no caller, or reaches only some.

    Three cases, whatever spelling made them: a name a module never bound,
    which ``raising=False``, ``create=True`` or a write to the namespace makes
    of a stale target; a package's binding of its own submodule replaced,
    which no caller reads; and an object bound in several modules patched or
    deleted in some of them, which leaves the rest on the original. A
    re-export rebound is the fourth, refused with its owners as advice.
    """
    problems: list[str] = []
    for layout in LAYOUTS:
        before = snapshot.modules[layout.name]
        problems += layout.rebound(
            {name: ident for name, ident in before.items() if name in layout.owners()}
        )
        namespace = vars(layout.package)
        for name in before:
            full = f"{layout.name}.{name}"
            if full in snapshot.modules and namespace.get(name) is not sys.modules.get(
                full
            ):
                problems.append(
                    f"{full} was rebound on its package; no caller reads that "
                    "binding. Patch each binding a caller reads, in the module."
                )
    for module_name, before in snapshot.modules.items():
        module = sys.modules.get(module_name)
        if module is None:
            continue
        package = sys.modules[module_name.rpartition(".")[0]]
        for name, value in vars(module).items():
            if name.startswith("__") or name in before:
                continue
            if module_name in _BY_NAME and _is_own_submodule(module, name, value):
                continue
            problems.append(
                f"{module_name} never bound {name}, so binding it reaches no "
                "caller. Patch each binding a caller reads, in the modules under "
                f"{package.__name__.replace('.', '/')}/."
            )
    for group in snapshot.groups:
        now = {target: id(_resolve(target)) for target in group}
        if len(set(now.values())) > 1:
            originals = {
                target: snapshot.modules[target.rpartition(".")[0]][
                    target.rpartition(".")[2]
                ]
                for target in group
            }
            patched = [t for t in group if now[t] != originals[t]]
            missed = [t for t in group if now[t] == originals[t]]
            problems.append(
                f"patched or deleted {', '.join(patched)} but not "
                f"{', '.join(missed)}; "
                "each is read by the code in its own module, so patch them all."
            )
    return problems


#: What a binding a test deleted resolves to.
_DELETED = object()


def _resolve(target: str) -> object:
    module, _, name = target.rpartition(".")
    return getattr(sys.modules.get(module), name, _DELETED)


#: Whether a patch was applied since bindings were last checked, and what the
#: checks made while patches were undone found.
_WATCH: dict[str, Any] = {"dirty": False, "found": []}


def _patched() -> None:
    _WATCH["dirty"] = True


def _before_undo() -> None:
    """Check bindings once, while every patch is still in place.

    A ``with`` block, ``monkeypatch.context()`` or ``patch.stop()`` undoes its
    patch before the test returns, so a check made only then sees nothing.
    Checking at the first undo after a patch, and not again until another
    patch, sees the patches together, as an ``ExitStack`` unwinding them one by
    one does not.
    """
    if _WATCH["dirty"] and "snapshot" in _HELD:
        _WATCH["dirty"] = False
        _WATCH["found"] += binding_problems(_HELD["snapshot"])


def take_found() -> list[str]:
    """What the checks made since the last call found, now cleared."""
    found, _WATCH["found"] = _WATCH["found"], []
    return found


def check_bindings() -> list[str]:
    """Everything found so far, and what a check now finds."""
    _WATCH["dirty"] = False
    found = take_found()
    if "snapshot" in _HELD:
        found += binding_problems(_HELD["snapshot"])
    return found


def _watch_patches() -> None:
    """Mark every patch applied, and check bindings before one is undone."""
    from _pytest.monkeypatch import MonkeyPatch

    patch_class: Any = mock._patch  # type: ignore[attr-defined]
    patch_dict_class: Any = mock._patch_dict  # type: ignore[attr-defined]
    originals = {
        (patch_class, "__enter__"): patch_class.__enter__,
        (patch_class, "__exit__"): patch_class.__exit__,
        (patch_dict_class, "_unpatch_dict"): patch_dict_class._unpatch_dict,
        (MonkeyPatch, "setattr"): MonkeyPatch.setattr,
        (MonkeyPatch, "delattr"): MonkeyPatch.delattr,
        (MonkeyPatch, "undo"): MonkeyPatch.undo,
    }
    _HELD["watched"] = originals

    def applies(original: Any) -> Any:
        @functools.wraps(original)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return original(*args, **kwargs)
            finally:
                _patched()

        return wrapper

    def undoes(original: Any) -> Any:
        @functools.wraps(original)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            _before_undo()
            return original(*args, **kwargs)

        return wrapper

    patch_class.__enter__ = applies(originals[(patch_class, "__enter__")])
    patch_class.__exit__ = undoes(originals[(patch_class, "__exit__")])
    patch_dict_class._unpatch_dict = undoes(
        originals[(patch_dict_class, "_unpatch_dict")]
    )
    MonkeyPatch.setattr = applies(originals[(MonkeyPatch, "setattr")])  # type: ignore[method-assign]
    MonkeyPatch.delattr = applies(originals[(MonkeyPatch, "delattr")])  # type: ignore[method-assign]
    MonkeyPatch.undo = undoes(originals[(MonkeyPatch, "undo")])  # type: ignore[method-assign]
