# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""No test rebinds a name on ``ori.config`` itself.

``ori.config`` only re-exports; the code that calls a helper runs in the
section module that defines it. A patch on the re-export never reaches that
caller, so the test passes whether or not the behaviour it targets holds.
``tests/config_layout.py`` refuses every such rebinding while the suite runs,
and the conftest fails a test that rebound one through the module's dict.
These tests drive that guard through each spelling of a patch.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path
from unittest import mock

import pytest

import ori.config
from tests.config_layout import bindings, rebound

REFUSED = "is a re-export; rebinding it reaches no caller"


def test_the_guard_is_installed() -> None:
    assert type(ori.config).__name__ == "_ReexportsHeld"


@pytest.mark.parametrize(
    "rebind",
    [
        pytest.param(
            lambda mp: mp.setattr("ori.config._detect_host_timezone", None),
            id="setattr-string",
        ),
        pytest.param(
            # A string target takes its value through ``name``.
            lambda mp: mp.setattr(target="ori.config._parse_device", name=None),
            id="setattr-keyword",
        ),
        pytest.param(
            lambda mp: mp.setattr(ori.config, "_parse_gateway", None),
            id="setattr-object",
        ),
        pytest.param(
            lambda mp: mp.setattr(ori.config, name="_parse_hal", value=None),
            id="setattr-object-keyword",
        ),
        pytest.param(
            lambda mp: mp.setattr("ori.config." + "_parse_skills", None),
            id="setattr-concatenated",
        ),
        pytest.param(
            lambda mp: mp.setattr(
                importlib.import_module("ori.config"), "Config", None
            ),
            id="setattr-import-module",
        ),
        pytest.param(
            lambda mp: mp.delattr("ori.config._parse_state"), id="delattr-string"
        ),
        pytest.param(
            lambda mp: setattr(ori.config, "_MAX_CONFIG_BYTES", 1), id="assignment"
        ),
        pytest.param(
            lambda mp: mock.patch("ori.config._parse_sensors").start(),
            id="mock-patch",
        ),
        pytest.param(
            lambda mp: mock.patch.object(ori.config, "is_truthy").start(),
            id="mock-patch-object",
        ),
        pytest.param(
            lambda mp: mock.patch.multiple("ori.config", _parse_logging=None).start(),
            id="mock-patch-multiple",
        ),
    ],
)
def test_every_attribute_spelling_is_refused(
    monkeypatch: pytest.MonkeyPatch, rebind
) -> None:
    before = bindings()
    try:
        with pytest.raises(AssertionError, match=REFUSED) as refused:
            rebind(monkeypatch)
    finally:
        mock.patch.stopall()
    assert "Patch ori.config._" in str(refused.value)
    assert rebound(before) == []


def test_a_write_into_the_module_dict_is_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one spelling that bypasses the class, caught when the test ends."""
    before = bindings()
    monkeypatch.setitem(vars(ori.config), "_parse_actions", None)
    problems = rebound(before)
    monkeypatch.undo()
    assert problems == [
        "ori.config._parse_actions is a re-export; rebinding it reaches no "
        "caller. Patch ori.config._actions instead."
    ]
    assert rebound(before) == []


def test_patching_the_owning_module_is_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("ori.config._device._detect_host_timezone", lambda: None)
    monkeypatch.setattr("ori.config.Config.load", lambda *a, **k: None)


TESTS = Path(__file__).resolve().parent


def _is_package(node: ast.AST, aliases: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in aliases
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "config"
        and isinstance(node.value, ast.Name)
        and node.value.id == "ori"
    )


def _is_package_dict(node: ast.AST, aliases: set[str]) -> bool:
    """``ori.config.__dict__`` or ``vars(ori.config)``, under any alias."""
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return _is_package(node.value, aliases)
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "vars"
        and len(node.args) == 1
        and _is_package(node.args[0], aliases)
    )


def dict_patches(root: Path) -> list[str]:
    """``patch.dict`` or ``setitem`` calls on ``ori.config``'s namespace.

    The one spelling neither guard sees: a ``with mock.patch.dict(...)`` block
    restores the namespace before the test ends, and writes it without going
    through the module's class.
    """
    found = []
    for path in sorted(root.rglob("*.py")):
        if path == Path(__file__).resolve():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        aliases = (
            {"config"}
            if any(
                isinstance(n, ast.ImportFrom)
                and n.module == "ori"
                and any(a.name == "config" and a.asname is None for a in n.names)
                for n in ast.walk(tree)
            )
            else set()
        )
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                aliases |= {
                    a.asname for a in node.names if a.name == "ori.config" and a.asname
                }
            elif isinstance(node, ast.ImportFrom) and node.module == "ori":
                aliases |= {
                    a.asname for a in node.names if a.name == "config" and a.asname
                }
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"dict", "setitem"}
                and node.args
                and _is_package_dict(node.args[0], aliases)
            ):
                found.append(f"{path.relative_to(root.parent)}:{node.lineno}")
    return found


def test_no_test_patches_the_namespace_of_ori_config() -> None:
    found = dict_patches(TESTS)
    assert not found, (
        "patch the section module that defines the name, not ori.config's "
        "namespace: " + ", ".join(found)
    )


def test_the_namespace_scan_finds_each_spelling(tmp_path: Path) -> None:
    (tmp_path / "test_x.py").write_text(
        "import ori.config\n"
        "import ori.config as cfg\n"
        "from unittest import mock\n"
        "def test(monkeypatch):\n"
        "    with mock.patch.dict(ori.config.__dict__, {}):\n"
        "        pass\n"
        "    mock.patch.dict(vars(cfg), {})\n"
        "    monkeypatch.setitem(vars(ori.config), 'x', 1)\n"
        "    monkeypatch.setitem(cfg.__dict__, 'x', 1)\n"
        "    mock.patch.dict(ori.config._device.__dict__, {})\n"
    )
    assert len(dict_patches(tmp_path)) == 4
