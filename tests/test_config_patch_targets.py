# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""No test patches a name on ``ori.config`` itself.

``ori.config`` only re-exports; the code that calls a helper runs in the
section module that defines it. A patch on the re-export never reaches that
caller, so the test passes whether or not the behaviour it targets holds.
Every such target is refused here, naming the module to patch instead.
"""

from __future__ import annotations

import ast
from pathlib import Path

import ori.config
from tests.config_layout import config_owners, section_modules

TESTS = Path(__file__).resolve().parent
PACKAGE = ori.config.__name__

#: Callables whose first argument is a dotted target string.
_STRING_TARGET_CALLS = frozenset({"setattr", "delattr", "patch"})
#: Callables whose first two arguments are an object and an attribute name.
_OBJECT_TARGET_CALLS = frozenset({"setattr", "delattr", "object"})


def _module_aliases(tree: ast.Module) -> set[str]:
    """Local names bound to the ``ori.config`` module object in one file."""
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == PACKAGE and alias.asname:
                    aliases.add(alias.asname)
        elif isinstance(node, ast.ImportFrom) and node.module == "ori":
            for alias in node.names:
                if alias.name == "config":
                    aliases.add(alias.asname or alias.name)
    return aliases


def _is_package_ref(node: ast.AST, aliases: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in aliases
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "config"
        and isinstance(node.value, ast.Name)
        and node.value.id == "ori"
    )


def _called(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _targets(tree: ast.Module) -> list[tuple[int, str]]:
    """(line, name) for every patch aimed at a name bound on ``ori.config``."""
    aliases = _module_aliases(tree)
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        called = _called(node)
        if called in _STRING_TARGET_CALLS:
            target = _string(node.args[0])
            prefix = f"{PACKAGE}."
            if target and target.startswith(prefix):
                rest = target.removeprefix(prefix)
                if "." not in rest:
                    found.append((node.lineno, rest))
                    continue
        if (
            called in _OBJECT_TARGET_CALLS
            and len(node.args) >= 2
            and _is_package_ref(node.args[0], aliases)
        ):
            name = _string(node.args[1])
            if name:
                found.append((node.lineno, name))
    return found


def patches_on_the_package(root: Path) -> list[str]:
    owners = config_owners()
    sections = {
        module.__name__.removeprefix(f"{PACKAGE}.") for module in section_modules()
    }
    problems = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for line, name in _targets(tree):
            if name in sections:
                continue  # the section module itself, not a name re-exported from it
            where = ", ".join(owners.get(name, ())) or "the module that reads it"
            problems.append(
                f"{path.relative_to(root.parent).as_posix()}:{line}: patches "
                f"{PACKAGE}.{name}; patch {where} instead"
            )
    return problems


def test_no_test_patches_a_re_export_of_ori_config() -> None:
    problems = patches_on_the_package(TESTS)
    assert not problems, "\n".join(problems)


def test_the_scan_finds_each_spelling(tmp_path: Path) -> None:
    """The guard is only as good as the spellings it recognises."""
    (tmp_path / "test_x.py").write_text(
        "import ori.config as cfg\n"
        "from ori import config\n"
        "from unittest import mock\n"
        "def test(monkeypatch):\n"
        '    monkeypatch.setattr("ori.config._detect_host_timezone", None)\n'
        '    mock.patch("ori.config._parse_device")\n'
        '    mock.patch.object(cfg, "_parse_gateway")\n'
        '    monkeypatch.setattr(config, "_MAX_CONFIG_BYTES", 1)\n'
        '    monkeypatch.setattr(ori.config, "is_truthy", None)\n'
        '    monkeypatch.setattr("ori.config._device._detect_host_timezone", None)\n'
        '    monkeypatch.setattr("ori.config.Config.load", None)\n'
    )
    problems = patches_on_the_package(tmp_path)
    assert len(problems) == 5, problems
    assert "patch ori.config._device instead" in problems[0]
    assert "patch ori.config._document instead" in problems[3]
