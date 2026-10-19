# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Where the state store's code lives, for tests that read or patch it.

``StateStore`` is composed from one class per domain, each in its own module
under ``ori/state/``. A guard that reads one file, or a patch on one module,
sees only part of the store and can pass while checking nothing. Derive the
layout from here instead.
"""

from __future__ import annotations

import ast
import contextlib
import functools
import importlib
import inspect
from pathlib import Path
from typing import Callable, Iterator

import pytest

from ori.state.store import StateStore
from ori.utils import time_utils

ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = ROOT / "ori" / "state"


def state_store_classes() -> tuple[tuple[str, str], ...]:
    """(repository-relative path, class name) for every class StateStore is built from."""
    found = []
    for cls in StateStore.__mro__[:-1]:
        source = inspect.getsourcefile(cls)
        assert source is not None, cls
        found.append(
            (Path(source).resolve().relative_to(ROOT).as_posix(), cls.__name__)
        )
    assert len(found) > 2, found
    return tuple(found)


def state_store_modules() -> tuple[str, ...]:
    """Repository-relative paths of the modules the store is made of.

    ``store.py`` and its private ``_*.py`` modules; ``deferred_writer.py`` is a
    separate component the store uses.
    """
    paths = [STATE_DIR / "store.py", *sorted(STATE_DIR.glob("_*.py"))]
    modules = tuple(
        p.relative_to(ROOT).as_posix() for p in paths if p.name != "__init__.py"
    )
    assert {path for path, _ in state_store_classes()} <= set(modules), modules
    return modules


@functools.cache
def _clock_modules() -> tuple[object, ...]:
    """Store modules that import ``now_ms`` from ``ori.utils.time_utils``.

    Read from source, so a clock already frozen does not hide a module from a
    second freeze. A module reading the clock any other way is not found.
    """
    modules = []
    for rel in state_store_modules():
        tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"))
        if any(
            isinstance(node, ast.ImportFrom)
            and node.module == time_utils.__name__
            and any(
                alias.name == "now_ms" and alias.asname is None for alias in node.names
            )
            for node in tree.body
        ):
            modules.append(
                importlib.import_module(rel.removesuffix(".py").replace("/", "."))
            )
    assert len(modules) > 1, "no store module reads the clock"
    return tuple(modules)


def freeze_store_clock(
    monkeypatch: pytest.MonkeyPatch, clock: Callable[[], int]
) -> None:
    """Make every store module read *clock* for the current time."""
    for module in _clock_modules():
        monkeypatch.setattr(module, "now_ms", clock)


@contextlib.contextmanager
def store_clock_at(timestamp: int) -> Iterator[None]:
    """Hold every store module's clock at *timestamp* for the block."""
    with pytest.MonkeyPatch.context() as monkeypatch:
        freeze_store_clock(monkeypatch, lambda: timestamp)
        yield
