# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""No branch is keyed on a condition the type checker evaluates statically.

pyright's `reportUnreachable` reports code that type analysis rules out, and
the project gates it. pyright exempts code ruled out by a *static* condition:
a comparison of `sys.platform`, `os.name` or `sys.version_info`, a branch on
`TYPE_CHECKING` other than its body, and a falsy literal such as `if False:`.
It neither reports nor type-checks that code, so on the platform it analyses
for (Linux) a macOS branch written that way is read by nothing.

This guard scans every expression in a module, outside decorator arguments
(which are expressions, not regions), through whatever name the module binds
`sys`, `os`, `typing`, `typing_extensions` or `TYPE_CHECKING` to. It refuses
every static comparison and every mention of `TYPE_CHECKING` except a bare
`if TYPE_CHECKING:` with no else, whose body pyright checks; and a constant
wherever it decides whether other code runs. It also refuses
`sys.platform.startswith(...)`, which pyright does check, so the platform is
read one way: through `ori.utils.platform`.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNED = ("ori", "scripts", "tests")

_LIMIT = (
    "Read the platform through ori.utils.platform (runtime_platform(), "
    "os_name(), runtime_version_info()), which no checker narrows, and import "
    "unconditionally rather than through a TYPE_CHECKING else. This guard "
    "resolves the names a module binds with `import sys/os/typing/"
    "typing_extensions [as X]` and `from typing|typing_extensions import "
    "TYPE_CHECKING [as X]`. A static value reached any other way, such as "
    "another module's re-export, or a name pyright's `defineConstant` setting "
    "makes static, is outside it."
)


@dataclass
class _Bindings:
    """The names one module binds to the modules and flag pyright evaluates."""

    sys: set[str] = field(default_factory=lambda: {"sys"})
    os: set[str] = field(default_factory=lambda: {"os"})
    typing: set[str] = field(default_factory=lambda: {"typing"})
    type_checking: set[str] = field(default_factory=lambda: {"TYPE_CHECKING"})


def _bindings(tree: ast.AST) -> _Bindings:
    bound = _Bindings()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                target = {
                    "sys": bound.sys,
                    "os": bound.os,
                    "typing": bound.typing,
                    "typing_extensions": bound.typing,
                }
                if alias.name in target:
                    target[alias.name].add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module in (
            "typing",
            "typing_extensions",
        ):
            for alias in node.names:
                if alias.name == "TYPE_CHECKING":
                    bound.type_checking.add(alias.asname or alias.name)
    return bound


def _is_attr(node: ast.AST, modules: set[str], name: str) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == name
        and isinstance(node.value, ast.Name)
        and node.value.id in modules
    )


def _mentions_type_checking(node: ast.AST, bound: _Bindings) -> bool:
    return (isinstance(node, ast.Name) and node.id in bound.type_checking) or (
        _is_attr(node, bound.typing, "TYPE_CHECKING")
    )


def _static(node: ast.AST, bound: _Bindings) -> bool:
    """An expression pyright evaluates against its configured platform."""
    if isinstance(node, ast.Compare):
        for operand in (node.left, *node.comparators):
            target = operand.value if isinstance(operand, ast.Subscript) else operand
            if (
                _is_attr(target, bound.sys, "platform")
                or _is_attr(target, bound.os, "name")
                or _is_attr(target, bound.sys, "version_info")
            ):
                return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "startswith"
        and _is_attr(node.func.value, bound.sys, "platform")
    )


def _deciding_positions(tree: ast.AST) -> list[tuple[ast.AST, ast.expr]]:
    """Every expression whose value decides whether other code runs."""
    found: list[tuple[ast.AST, ast.expr]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.While, ast.IfExp, ast.Assert)):
            found.append((node, node.test))
        elif isinstance(node, ast.comprehension):
            found.extend((node, test) for test in node.ifs)
        elif isinstance(node, ast.match_case) and node.guard is not None:
            found.append((node, node.guard))
        elif isinstance(node, ast.BoolOp):
            found.extend((node, value) for value in node.values[:-1])
    return found


# Values pyright decides without running anything: a constant, and a display,
# whose truth is its emptiness, however it is built.
_LITERALS = (ast.Constant, ast.List, ast.Tuple, ast.Set, ast.Dict)


def _unwrap_not(test: ast.expr) -> tuple[int, ast.expr]:
    """The operand under any chain of `not` and `:=`, and how many `not`s."""
    negations = 0
    while True:
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            test = test.operand
            negations += 1
        elif isinstance(test, ast.NamedExpr):
            test = test.value
        else:
            return negations, test


def _decided_by_literal(test: ast.expr) -> bool:
    """A condition a literal decides: the literal itself, under any `not` or
    `:=`, or an `and`/`or` with such an operand at any depth, its last included.

    This refuses more than pyright exempts: pyright treats `x or False` and
    `x and True` as undecided and checks both branches. Refusing them errs on
    the side of keeping every branch checked, and each can be written without
    the literal.
    """
    _negations, value = _unwrap_not(test)
    if isinstance(value, _LITERALS):
        return True
    return isinstance(value, ast.BoolOp) and any(
        _decided_by_literal(operand) for operand in value.values
    )


# Inside a decorator these contain regions a static value can rule out, so
# they are scanned like any other code.
_REGIONS = (
    ast.IfExp,
    ast.Lambda,
    ast.BoolOp,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
)


def _decorators(tree: ast.AST) -> set[int]:
    """Decorator argument nodes that are plain expressions, never regions.

    A predicate such as `skipif(runtime_platform() != "linux")` is evaluated,
    not branched on. A conditional expression, lambda, `and`/`or` or
    comprehension inside a decorator is a region, and is not exempt.
    """
    inside: set[int] = set()

    def plain(node: ast.AST) -> None:
        if isinstance(node, _REGIONS):
            return
        inside.add(id(node))
        for child in ast.iter_child_nodes(node):
            plain(child)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for decorator in node.decorator_list:
                plain(decorator)
    return inside


def _bare_type_checking_body(node: ast.AST, bound: _Bindings) -> bool:
    return (
        isinstance(node, ast.If)
        and _mentions_type_checking(node.test, bound)
        and not node.orelse
    )


def _offences(path: Path, root: Path = ROOT) -> list[int]:
    """Lines of every expression pyright would evaluate statically.

    Static comparisons and TYPE_CHECKING are refused wherever they appear,
    outside decorator arguments, so no position needs listing; a constant is
    refused where it decides whether other code runs. The one form allowed is
    a bare `if TYPE_CHECKING:` with no else, whose body pyright checks.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    bound = _bindings(tree)
    skip = _decorators(tree)
    allowed: set[int] = set()
    for node in ast.walk(tree):
        if _bare_type_checking_body(node, bound):
            assert isinstance(node, ast.If)
            allowed.update(id(sub) for sub in ast.walk(node.test))
    lines: set[int] = set()
    for node in ast.walk(tree):
        if id(node) in skip or id(node) in allowed:
            continue
        if _static(node, bound) or _mentions_type_checking(node, bound):
            lines.add(getattr(node, "lineno", 0))
    for owner, test in _deciding_positions(tree):
        if id(test) in skip:
            continue
        negations, value = _unwrap_not(test)
        if isinstance(owner, ast.BoolOp):
            # A free-standing operand: only a literal decides what follows it.
            if not isinstance(value, _LITERALS):
                continue
        elif not _decided_by_literal(test):
            continue
        if (
            isinstance(owner, ast.While)
            and not negations
            and isinstance(value, ast.Constant)
            and value.value
        ):
            continue  # `while True:` - code after it is reported by type analysis
        lines.add(test.lineno)
    return sorted(lines)


def test_no_branch_is_keyed_on_a_statically_evaluated_condition() -> None:
    offences = [
        f"{path.relative_to(ROOT)}:{line}"
        for directory in SCANNED
        for path in sorted((ROOT / directory).rglob("*.py"))
        if "vectors" not in path.parts
        for line in _offences(path)
    ]
    assert not offences, (
        f"branches the type checker neither reports nor checks: {offences}. {_LIMIT}"
    )


_PROBE = """\
import os, sys, typing
import sys as _sys
import typing_extensions
from typing import TYPE_CHECKING
from typing import TYPE_CHECKING as _TC
if sys.platform == "darwin": pass  # refuse
if sys.platform != "linux": pass  # refuse
if sys.platform.startswith("linux"): pass  # refuse
if os.name == "nt": pass  # refuse
if sys.version_info < (3, 11): pass  # refuse
if sys.version_info[0] == 3: pass  # refuse
if False: pass  # refuse
x = 1 if sys.platform == "win32" else 2  # refuse
while sys.platform == "darwin": break  # refuse
y = [i for i in range(3) if sys.platform == "darwin"]  # refuse
if _sys.platform == "darwin": pass  # refuse
if typing.TYPE_CHECKING: pass  # refuse
else: pass
if not TYPE_CHECKING: pass  # refuse
if 0: pass  # refuse
if None: pass  # refuse
if _TC: pass  # refuse
else: pass
assert not TYPE_CHECKING  # refuse
assert sys.version_info < (3, 11), "old"  # refuse
z = sys.platform == "linux" or print("never checked")  # refuse
w = False and print("never checked")  # refuse
match x:
    case 1 if sys.platform == "darwin": pass  # refuse
    case 2 if False: pass  # refuse
assert 0  # refuse
if not True: pass  # refuse
while not True: break  # refuse
if not not False: pass  # refuse
if []: pass  # refuse
if (x,): pass  # refuse
else: pass
if {}: pass  # refuse
u = () and print("never checked")  # refuse
if x and False: pass  # refuse
while x and False: break  # refuse
if not (x or True): pass  # refuse
assert f() and False  # refuse
if (z := False): pass  # refuse
if typing_extensions.TYPE_CHECKING: pass  # refuse
else: pass
LINUX = sys.platform.startswith("linux")  # refuse
if TYPE_CHECKING:
    import json
while True: break
if cfg.get("x", False) or y is False: pass
if platform == "darwin": pass
v = flag and False
@pytest.mark.skipif(sys.platform != "linux", reason="decorator: an expression")
def t(): pass
@decorate(lambda: "bad" + 1 if False else 1)  # refuse
def t2(): pass
@decorate(lambda: 1 if sys.platform == "darwin" else 2)  # refuse
def t3(): pass
@decorate(1 if sys.platform == "darwin" else 2)  # refuse
def t4(): pass
@decorate(sys.platform == "linux" or f())  # refuse
def t5(): pass
@decorate([i for i in range(3) if False])  # refuse
def t6(): pass
"""


def _expected(source: str) -> list[int]:
    return [
        number
        for number, line in enumerate(source.splitlines(), start=1)
        if line.endswith("# refuse")
    ]


def test_the_guard_refuses_each_shape_it_names(tmp_path: Path) -> None:
    """Driven through `_offences` itself, on a file, so every scan is exercised.

    Each line marked `# refuse` must be refused, and nothing else: the
    unmarked lines are the forms pyright checks, or expressions that are not
    regions, which the guard must leave alone.
    """
    probe = tmp_path / "probe.py"
    probe.write_text(_PROBE, encoding="utf-8")
    assert _offences(probe, tmp_path) == _expected(_PROBE)
