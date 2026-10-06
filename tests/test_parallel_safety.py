# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Tests that build from the repository share one xdist worker.

CI runs the suite across workers. A build writes into the repository itself
(`build/`, `*.egg-info`, a cargo `target/`), so two workers building at once
collide, and only intermittently. Every test that builds, directly or through
a fixture, carries `xdist_group("repo_build")`, and `--dist loadgroup` runs the
group on one worker.
"""

from __future__ import annotations

import ast
from pathlib import Path

TESTS = Path(__file__).resolve().parent
GROUP = "repo_build"


def _is_build(node: ast.AST) -> bool:
    """A literal argument list that builds a wheel or a crate."""
    if not isinstance(node, ast.List):
        return False
    words = [
        e.value
        for e in node.elts
        if isinstance(e, ast.Constant) and isinstance(e.value, str)
    ]
    pairs = set(zip(words, words[1:]))
    return bool(pairs & {("-m", "build"), ("pip", "wheel"), ("cargo", "build")})


def _grouped(decorators: list[ast.expr]) -> bool:
    for decorator in decorators:
        for node in ast.walk(decorator):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "xdist_group"
                and any(
                    isinstance(a, ast.Constant) and a.value == GROUP for a in node.args
                )
            ):
                return True
    return False


def _module_grouped(tree: ast.Module) -> bool:
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets
        ):
            return _grouped([node.value])
    return False


def _ungrouped_builders() -> list[str]:
    found = []
    for path in sorted(TESTS.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if _module_grouped(tree):
            continue
        scopes: list[tuple[list[ast.stmt], list[ast.expr]]] = [(tree.body, [])]
        scopes += [
            (node.body, node.decorator_list)
            for node in tree.body
            if isinstance(node, ast.ClassDef)
        ]
        for body, inherited in scopes:
            functions = [
                n
                for n in body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            builders = {
                f.name for f in functions if any(_is_build(n) for n in ast.walk(f))
            }
            module_builders = {
                f.name
                for f in tree.body
                if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))
                and any(_is_build(n) for n in ast.walk(f))
            }
            for function in functions:
                uses = {a.arg for a in function.args.args} & (
                    builders | module_builders
                )
                builds = function.name in builders
                if (
                    function.name.startswith("test")
                    and (builds or uses)
                    and not _grouped(function.decorator_list + inherited)
                ):
                    rel = path.relative_to(TESTS.parent).as_posix()
                    found.append(f"{rel}::{function.name}")
    return found


def test_every_test_that_builds_from_the_repository_shares_one_worker() -> None:
    ungrouped = _ungrouped_builders()
    assert not ungrouped, (
        f'Mark these with @pytest.mark.xdist_group("{GROUP}"): they build a wheel or a crate '
        "from the repository, and two workers building at once collide. This guard sees "
        "literal `-m build`, `pip wheel` and `cargo build` argument lists in a test, a test "
        f"method, or a same-module fixture the test takes; ungrouped: {ungrouped}"
    )


def test_the_guard_sees_the_builders_it_was_written_for() -> None:
    texts = {
        p.relative_to(TESTS.parent).as_posix(): p.read_text(encoding="utf-8")
        for p in TESTS.rglob("*.py")
    }
    seen = {
        rel
        for rel, text in texts.items()
        if any(_is_build(n) for n in ast.walk(ast.parse(text)))
    }
    assert {
        "tests/evidence/test_disclosure.py",
        "tests/test_linux_installer.py",
        "tests/test_runtime_mobile_delivery_e2e.py",
    } <= seen, f"the guard no longer recognises a known builder; it sees {sorted(seen)}"
