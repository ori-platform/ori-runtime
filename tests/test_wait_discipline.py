# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""No test may let a bounded wait run out silently and then assert.

A test that bounds a wait and carries on when the bound runs out reaches its
assertion before the work it asserts on whenever the runner is slow, and fails
there without any product defect. Every shape below has done exactly that in
this suite. Each one waits for the condition instead through
`tests/waiting.py`, whose deadline only bounds a hang and fails naming what was
awaited.

Read by AST, so a rename or a reformat does not slip past it, and limited to
the shapes it can name. It cannot see a fixed `asyncio.sleep` followed by an
assertion on another task's work, which is the same defect in its plainest
form; `ORI_TEST_STALL_MS` (see `tests/conftest.py`) is what exposes those.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

TESTS = Path(__file__).resolve().parent

#: The helpers themselves, which are the one place these shapes are correct.
_EXEMPT_FILES = frozenset({"waiting.py"})

#: (path relative to tests/, rule, enclosing function) -> why it is sound.
#: Every entry is a decision: a bound that runs out here cannot reach an
#: assertion as though the awaited work had happened.
ALLOWED: dict[tuple[str, str, str], str] = {}

_HELP = (
    "Wait for the condition itself with tests/waiting.py — wait_until(predicate, "
    "what=...), settle(tasks, what=...), drained(dispatcher) or quiesce(what=...) — "
    "which fail naming what never happened. This guard reads a few shapes only: "
    "a fixed asyncio.sleep followed by an assertion on another task's work is the "
    "same defect and passes it, so run the touched tests under ORI_TEST_STALL_MS "
    "as well."
)


def _names(node: ast.AST) -> set[str]:
    """Every identifier and attribute name under *node*."""
    found: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            found.add(child.id)
        elif isinstance(child, ast.Attribute):
            found.add(child.attr)
    return found


def _is_timeout_error(node: ast.AST) -> bool:
    return bool(_names(node) & {"TimeoutError"})


def _is_call_to(node: ast.AST, attr: str, owner: str | None = None) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr == attr:
        return owner is None or (
            isinstance(func.value, ast.Name) and func.value.id == owner
        )
    return isinstance(func, ast.Name) and func.id == attr and owner is None


def _awaits_sleep(node: ast.AST) -> bool:
    return any(
        isinstance(child, ast.Await) and _is_call_to(child.value, "sleep")
        for child in ast.walk(node)
    )


def _reads_a_clock(node: ast.AST) -> bool:
    names = _names(node)
    return bool(
        names & {"monotonic", "perf_counter", "deadline"}
        or any("deadline" in name for name in names)
        or ("time" in names and any(_is_call_to(c, "time") for c in ast.walk(node)))
    )


class _Finder(ast.NodeVisitor):
    def __init__(self) -> None:
        self.found: list[tuple[int, str, str]] = []
        self._function: list[str] = ["<module>"]

    def _add(self, node: ast.AST, rule: str) -> None:
        self.found.append((getattr(node, "lineno", 0), rule, self._function[-1]))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function.append(node.name)
        self.generic_visit(node)
        self._function.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function.append(node.name)
        self.generic_visit(node)
        self._function.pop()

    def visit_With(self, node: ast.With) -> None:
        self._check_suppress(node)
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._check_suppress(node)
        self.generic_visit(node)

    def _check_suppress(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            call = item.context_expr
            if _is_call_to(call, "suppress") and any(
                _is_timeout_error(arg)
                for arg in call.args  # type: ignore[attr-defined]
            ):
                self._add(node, "suppressed-timeout")

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        silent = all(
            isinstance(stmt, (ast.Pass, ast.Continue))
            or (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant))
            for stmt in node.body
        )
        if node.type is not None and _is_timeout_error(node.type) and silent:
            self._add(node, "swallowed-timeout")
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr) -> None:
        value = node.value
        if isinstance(value, ast.Await) and _is_call_to(value.value, "wait", "asyncio"):
            call = value.value
            assert isinstance(call, ast.Call)
            if any(kw.arg == "timeout" for kw in call.keywords) or len(call.args) > 1:
                self._add(node, "unchecked-asyncio-wait")
        if isinstance(value, ast.Await) and _is_call_to(value.value, "drain_records"):
            self._add(node, "unchecked-drain-records")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        value = node.value
        if (
            isinstance(value, ast.Await)
            and _is_call_to(value.value, "wait", "asyncio")
            and all(
                isinstance(t, ast.Name) and t.id == "_"
                for target in node.targets
                for t in (target.elts if isinstance(target, ast.Tuple) else [target])
            )
        ):
            self._add(node, "unchecked-asyncio-wait")
        self.generic_visit(node)

    def visit_Module(self, node: ast.Module) -> None:
        self._check_body(node.body)
        self.generic_visit(node)

    def generic_visit(self, node: ast.AST) -> None:
        for field in ("body", "orelse", "finalbody", "handlers"):
            block = getattr(node, field, None)
            if isinstance(block, list) and not isinstance(node, ast.Module):
                self._check_body(block)
        super().generic_visit(node)

    def _check_body(self, body: list[ast.stmt]) -> None:
        """A bounded poll that can fall out of its loop with nothing said."""
        for index, stmt in enumerate(body):
            if not isinstance(stmt, (ast.For, ast.While)) or stmt.orelse:
                continue
            if not _awaits_sleep(stmt):
                continue
            bounded = (isinstance(stmt, ast.While) and _reads_a_clock(stmt.test)) or (
                isinstance(stmt, ast.For)
                and _is_call_to(stmt.iter, "range")
                and any(isinstance(child, ast.Break) for child in ast.walk(stmt))
            )
            if not bounded:
                continue
            following = body[index + 1] if index + 1 < len(body) else None
            if isinstance(following, ast.Raise):
                continue
            self._add(stmt, "bounded-poll-falls-through")


def _violations() -> Iterator[str]:
    for path in sorted(TESTS.rglob("*.py")):
        if path.name in _EXEMPT_FILES:
            continue
        relative = path.relative_to(TESTS).as_posix()
        finder = _Finder()
        finder.visit(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)))
        for lineno, rule, function in finder.found:
            if (relative, rule, function) in ALLOWED:
                continue
            yield f"tests/{relative}:{lineno} ({function}): {rule}"


def _scan(source: str) -> list[str]:
    finder = _Finder()
    finder.visit(ast.parse(source))
    return [rule for _line, rule, _function in finder.found]


def test_no_test_lets_a_bounded_wait_run_out_silently() -> None:
    found = sorted(set(_violations()))
    assert not found, (
        "a wait whose bound can run out without failing, before an assertion:\n  "
        + "\n  ".join(found)
        + "\n"
        + _HELP
    )


def test_every_allowance_still_names_something() -> None:
    present: set[tuple[str, str, str]] = set()
    for path in sorted(TESTS.rglob("*.py")):
        if path.name in _EXEMPT_FILES:
            continue
        finder = _Finder()
        finder.visit(ast.parse(path.read_text(encoding="utf-8")))
        relative = path.relative_to(TESTS).as_posix()
        present |= {(relative, rule, fn) for _l, rule, fn in finder.found}
    stale = sorted(set(ALLOWED) - present)
    assert not stale, f"allowances that no longer match anything: {stale}"
    assert all(reason.strip() for reason in ALLOWED.values())


def test_the_guard_sees_each_shape_it_names() -> None:
    """Each rule, on the shape it was written for, and its corrected form."""
    cases = {
        "suppressed-timeout": (
            "async def t(task):\n"
            "    with contextlib.suppress(asyncio.TimeoutError):\n"
            "        await asyncio.wait_for(task, 5)\n"
        ),
        "swallowed-timeout": (
            "async def t(task):\n"
            "    try:\n"
            "        await asyncio.wait_for(task, 5)\n"
            "    except TimeoutError:\n"
            "        pass\n"
        ),
        "unchecked-asyncio-wait": (
            "async def t(pending):\n    await asyncio.wait(pending, timeout=2)\n"
        ),
        "unchecked-drain-records": (
            "async def t(d):\n    await d.drain_records(timeout=2)\n"
        ),
        "bounded-poll-falls-through": (
            "async def t(x):\n"
            "    deadline = time.monotonic() + 2\n"
            "    while time.monotonic() < deadline and not x:\n"
            "        await asyncio.sleep(0.05)\n"
            "    assert x\n"
        ),
    }
    for rule, source in cases.items():
        assert _scan(source) == [rule], (rule, _scan(source))
    sound = (
        "async def t(x, pending):\n"
        "    done, _ = await asyncio.wait(pending, timeout=2)\n"
        "    assert done\n"
        "    for _ in range(10):\n"
        "        if x:\n"
        "            break\n"
        "        await asyncio.sleep(0.01)\n"
        "    else:\n"
        "        raise AssertionError('never')\n"
        "    deadline = time.monotonic() + 2\n"
        "    while time.monotonic() < deadline:\n"
        "        if x:\n"
        "            return\n"
        "        await asyncio.sleep(0.05)\n"
        "    raise AssertionError('never')\n"
    )
    assert _scan(sound) == []
