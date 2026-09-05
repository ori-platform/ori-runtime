# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""No test may stop a runtime after guessing that startup got far enough.

The shape this refuses:

```python
async def _stop():
    await asyncio.sleep(0.1)
    await runtime.stop()

await asyncio.gather(runtime.start(), _stop())
```

The sleep is a guess. When startup is slower than the guess — a loaded runner,
a slower interpreter — the stop tears down a half-built runtime, and the
failure surfaces wherever startup happened to be rather than at the test that
caused it. One of these failed in CI as a bare `AssertionError` sixty lines
into the state store, from a pull request that does not touch the file
containing the test, and the time it costs is spent by whoever is unlucky
rather than by whoever wrote it.

A longer sleep makes it rarer and the suite slower and leaves the same failure
available on a slower machine. `tests/conftest.py::run_runtime_until` waits for
the state the test is about to assert on instead.

This guard exists because fixing the twelve that existed does not stop the
thirteenth being written, in this module or any other. It reads the whole test
tree, so a new one anywhere fails here rather than intermittently somewhere
else.
"""

from __future__ import annotations

import ast
from pathlib import Path

TESTS_ROOT = Path(__file__).resolve().parent


def _is_sleep(node: ast.AST) -> bool:
    """Whether this awaits a sleep, however the duration is written.

    Matching a literal duration would refuse `asyncio.sleep(0.1)` and admit
    `asyncio.sleep(_DELAY)`, which is the same guess with a name on it. The
    duration is not what makes it wrong; waiting for one at all is.

    Both spellings count: `asyncio.sleep(...)` and a bare `sleep(...)` from
    `from asyncio import sleep`.
    """
    if not isinstance(node, ast.Await) or not isinstance(node.value, ast.Call):
        return False
    func = node.value.func
    if isinstance(func, ast.Attribute):
        return func.attr == "sleep"
    return isinstance(func, ast.Name) and func.id == "sleep"


def _awaits_a_stop(node: ast.AST) -> bool:
    """Whether this subtree awaits something's `.stop()`."""
    for child in ast.walk(node):
        if (
            isinstance(child, ast.Await)
            and isinstance(child.value, ast.Call)
            and isinstance(child.value.func, ast.Attribute)
            and child.value.func.attr == "stop"
        ):
            return True
    return False


def _guessing_sleeps(function: ast.AST) -> list[int]:
    """Line numbers of straight-line sleeps in a function that then stops.

    A sleep inside a loop is a poll interval, not a guess: the surrounding
    loop is what waits for the state, and it carries its own deadline. Only a
    sleep on the straight-line path is asserting that a duration is long
    enough.
    """
    if not _awaits_a_stop(function):
        return []

    own: list[ast.AST] = []
    nested: set[int] = set()
    for node in ast.walk(function):
        # A nested `async def _stop()` is its own function and is reported
        # under its own name; walking into it here would report the same
        # sleep twice, once for the helper and once for the test around it.
        if node is not function and isinstance(
            node, (ast.AsyncFunctionDef, ast.FunctionDef, ast.Lambda)
        ):
            for inner in ast.walk(node):
                nested.add(id(inner))
    for node in ast.walk(function):
        if id(node) not in nested:
            own.append(node)

    looped: set[int] = set()
    for node in own:
        if isinstance(node, (ast.While, ast.For, ast.AsyncFor)):
            for inner in ast.walk(node):
                looped.add(id(inner))

    return [
        node.lineno
        for node in own
        if isinstance(node, ast.Await) and _is_sleep(node) and id(node) not in looped
    ]


def _offenders() -> list[str]:
    found: list[str] = []
    for path in sorted(TESTS_ROOT.rglob("test_*.py")):
        if path.name == Path(__file__).name:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
                continue
            for line in _guessing_sleeps(node):
                found.append(
                    f"{path.relative_to(TESTS_ROOT.parent)}:{line} "
                    f"in {node.name}() — sleeps, then stops a runtime"
                )
    return found


def test_no_test_stops_a_runtime_after_a_fixed_sleep() -> None:
    offenders = _offenders()
    assert offenders == [], (
        "These wait for time to pass and then stop a runtime, which races "
        "startup. Wait for the state being asserted on instead — "
        "`tests/conftest.py::run_runtime_until`:\n  " + "\n  ".join(offenders)
    )


def test_the_guard_recognises_the_shape_it_refuses() -> None:
    """A guard that cannot fail is not a guard.

    Asserted directly, because the suite passing tells us nothing about
    whether this would notice a thirteenth.
    """
    guessing = ast.parse(
        "async def _stop():\n    await asyncio.sleep(0.1)\n    await runtime.stop()\n"
    ).body[0]
    polling = ast.parse(
        "async def _stop():\n"
        "    while not ready():\n"
        "        await asyncio.sleep(0.02)\n"
        "    await runtime.stop()\n"
    ).body[0]
    unrelated = ast.parse(
        "async def _drive():\n    await asyncio.sleep(0.1)\n    task.cancel()\n"
    ).body[0]

    nested = ast.parse(
        "async def test_x():\n"
        "    async def _stop():\n"
        "        await asyncio.sleep(0.1)\n"
        "        await runtime.stop()\n"
        "    await asyncio.gather(runtime.start(), _stop())\n"
    ).body[0]

    named = ast.parse(
        "async def _stop():\n"
        "    await asyncio.sleep(_STARTUP_DELAY)\n"
        "    await runtime.stop()\n"
    ).body[0]
    aliased = ast.parse(
        "async def _stop():\n    await sleep(0.1)\n    await runtime.stop()\n"
    ).body[0]
    computed = ast.parse(
        "async def _stop():\n"
        "    await asyncio.sleep(_base * 2)\n"
        "    await runtime.stop()\n"
    ).body[0]

    assert _guessing_sleeps(guessing) == [2]
    # Reported once, under the helper that sleeps, not again under the test.
    assert _guessing_sleeps(nested) == []
    # A name on the duration is the same guess. So is importing `sleep`
    # directly, and so is computing the interval.
    assert _guessing_sleeps(named) == [2]
    assert _guessing_sleeps(aliased) == [2]
    assert _guessing_sleeps(computed) == [2]
    assert _guessing_sleeps(polling) == []
    assert _guessing_sleeps(unrelated) == []
