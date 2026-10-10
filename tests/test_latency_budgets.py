# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""A wall-clock budget asserts only where its clock measures the code.

Under parallel workers a test's wall clock measures the run's load as much as
the code, so a budget asserted there fails without any product defect. Every
budget is therefore asserted only under ``if latency_bounds_apply():``, which is
false in an xdist worker, and the modules that carry one run alone in CI's
"Run the latency budgets alone" step, where it holds.

A test that holds an obstruction proves it was never waited on by acting while
the obstruction is still held, for ``tests.waiting.HOLD_S`` with no shorter
timeout on the path, which no load can break; the budget is the speed claim on
top. A timestamp checked to be "now" is bracketed between two reads of its
clock, which no load can break either.

A budget is either of:

- a name ending ``_BOUND_S``, wherever it is read;
- an upper bound, in an assertion, on a duration: a difference whose two sides
  both read a clock (``time.monotonic``, ``perf_counter``, ``time.time``,
  ``loop.time``), directly or through local variables.

An ordering between timestamps, or a lower bound on a duration, only grows more
true under load and is not a budget.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
_BUDGET = re.compile(r"_BOUND_S$")
_STEP_MODULES = re.compile(r"tests/[a-z0-9_/]*test_[a-z0-9_]+\.py")
_CLOCKS = frozenset(
    {"monotonic", "monotonic_ns", "perf_counter", "perf_counter_ns", "time"}
)
_STEP = "Run the latency budgets alone"
_LIMIT = (
    " This guard sees a name ending _BOUND_S, and a duration computed in the same "
    "function from a clock read; a duration a fake or a helper computes, compared "
    "with a bare number, is not seen."
)


def _is_gate(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.If)
        and isinstance(node.test, ast.Call)
        and isinstance(node.test.func, ast.Name)
        and node.test.func.id == "latency_bounds_apply"
    )


def _is_clock(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _CLOCKS
        and not (
            isinstance(node.func.value, ast.Name) and node.func.value.id == "datetime"
        )
    )


def _reads(expr: ast.AST, names: set[str]) -> bool:
    return any(
        _is_clock(n) or (isinstance(n, ast.Name) and n.id in names)
        for n in ast.walk(expr)
    )


def _is_duration(expr: ast.AST, clocked: set[str], durations: set[str]) -> bool:
    for n in ast.walk(expr):
        if isinstance(n, ast.Name) and n.id in durations:
            return True
        if (
            isinstance(n, ast.BinOp)
            and isinstance(n.op, ast.Sub)
            and _reads(n.left, clocked)
            and _reads(n.right, clocked)
        ):
            return True
    return False


def _function_names(fn: ast.AST) -> tuple[set[str], set[str]]:
    """Locals assigned from a clock read, and locals holding a duration."""
    clocked: set[str] = set()
    durations: set[str] = set()
    for _ in range(4):
        for n in ast.walk(fn):
            if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                names = {
                    t.id
                    for target in targets
                    for t in ast.walk(target)
                    if isinstance(t, ast.Name)
                }
                if _is_duration(n.value, clocked, durations):
                    durations |= names
                if _reads(n.value, clocked):
                    clocked |= names
    return clocked, durations


def _bounds_a_duration_above(
    test: ast.AST, clocked: set[str], durations: set[str]
) -> bool:
    for c in ast.walk(test):
        if not isinstance(c, ast.Compare):
            continue
        terms = [c.left, *c.comparators]
        for i, op in enumerate(c.ops):
            low, high = terms[i], terms[i + 1]
            if isinstance(op, (ast.Lt, ast.LtE)) and _is_duration(
                low, clocked, durations
            ):
                return True
            if isinstance(op, (ast.Gt, ast.GtE)) and _is_duration(
                high, clocked, durations
            ):
                return True
    return False


def _ungated_budgets(tree: ast.AST) -> list[int]:
    found: list[int] = []

    def visit(node: ast.AST, gated: bool, names: tuple[set[str], set[str]]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names = _function_names(node)
        if not gated:
            if (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and _BUDGET.search(node.id)
            ):
                found.append(node.lineno)
            if isinstance(node, ast.Assert) and _bounds_a_duration_above(
                node.test, *names
            ):
                found.append(node.lineno)
        if _is_gate(node):
            assert isinstance(node, ast.If)
            visit(node.test, gated, names)
            for child in node.body:
                visit(child, True, names)
            for child in node.orelse:
                visit(child, gated, names)
            return
        for child in ast.iter_child_nodes(node):
            visit(child, gated, names)

    visit(tree, False, (set(), set()))
    return sorted(set(found))


def _modules() -> dict[str, ast.Module]:
    return {
        path.relative_to(ROOT).as_posix(): ast.parse(path.read_text())
        for path in sorted(TESTS.rglob("*.py"))
    }


def _gated_modules() -> set[str]:
    return {
        name
        for name, tree in _modules().items()
        if Path(name).name.startswith("test_")
        and name != "tests/test_latency_budgets.py"
        and any(_is_gate(node) for node in ast.walk(tree))
    }


def test_every_budget_is_asserted_only_under_the_gate() -> None:
    ungated = sorted(
        f"{name}:{line}"
        for name, tree in _modules().items()
        if name != "tests/test_latency_budgets.py"
        for line in _ungated_budgets(tree)
    )
    assert not ungated, (
        "a wall-clock budget is asserted outside `if latency_bounds_apply():`, so "
        f"it asserts under parallel workers, where it measures load: {ungated}. "
        "Gate it, or make it load-proof: act while the obstruction is held, or "
        "bracket a timestamp between two clock reads." + _LIMIT
    )


def _step_command(text: str) -> str:
    """The latency step's command: the line that starts it, and its continuation.

    In the workflow, the ``run:`` line and the indented lines under it; in the
    local script, the one ``step`` line naming it.
    """
    lines = text[text.rfind("\n", 0, text.index(_STEP)) + 1 :].splitlines()
    first = next(
        i
        for i, line in enumerate(lines)
        if line.lstrip().startswith("run:") or line.startswith("step ")
    )
    command = [lines[first]]
    for line in lines[first + 1 :]:
        if not line.strip() or not line.startswith(" "):
            break
        command.append(line)
    return "\n".join(command)


def test_no_budget_hides_behind_an_early_return() -> None:
    """`if not latency_bounds_apply(): return` gates what follows it unseen."""
    negated = sorted(
        f"{name}:{node.lineno}"
        for name, tree in _modules().items()
        for node in ast.walk(tree)
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.UnaryOp)
        and isinstance(node.test.op, ast.Not)
        and isinstance(node.test.operand, ast.Call)
        and isinstance(node.test.operand.func, ast.Name)
        and node.test.operand.func.id == "latency_bounds_apply"
    )
    assert not negated, (
        "write the gate as `if latency_bounds_apply():` around the budget, which "
        f"this guard reads; a negated gate is not: {negated}"
    )


def test_ci_runs_every_module_with_a_budget_alone() -> None:
    gated = _gated_modules()
    assert gated, "no module gates a budget; the scan is broken"
    for where in (".github/workflows/ci.yml", "scripts/ci_local.sh"):
        command = _step_command((ROOT / where).read_text())
        listed = set(_STEP_MODULES.findall(command))
        assert listed == gated, (
            f"{where}'s latency step must run exactly the modules that gate a "
            f"budget. Missing: {sorted(gated - listed)}; not gated: "
            f"{sorted(listed - gated)}. A module left out has budgets nothing "
            "asserts." + _LIMIT
        )
        assert "-p no:xdist" in command, f"{where}'s latency step must run serially"


def test_the_guard_sees_each_kind_of_budget() -> None:
    tree = ast.parse(
        "def t():\n"
        "    assert x < _TRIP_BOUND_S\n"
        "    if latency_bounds_apply():\n"
        "        assert y < _TRIP_BOUND_S\n"
        "    started = time.monotonic()\n"
        "    elapsed = time.monotonic() - started\n"
        "    assert elapsed < 0.5\n"
        "    assert time.monotonic() - started < 1.0\n"
        "    assert 2.0 > elapsed\n"
        "    assert elapsed >= 0.4\n"
        "    before = time.monotonic()\n"
        "    after = time.monotonic()\n"
        "    assert before <= value <= after\n"
        "    if latency_bounds_apply():\n"
        "        assert elapsed < 0.5\n"
    )
    assert _ungated_budgets(tree) == [2, 7, 8, 9]
