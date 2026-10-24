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
from tests.config_layout import bindings, config_owners, rebound

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
    assert "Patch each binding a caller reads instead: ori.config._" in str(
        refused.value
    )
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
        "caller. Patch each binding a caller reads instead: "
        "ori.config._actions.parse_actions, ori.config._config.parse_actions."
    ]
    assert rebound(before) == []


def test_patching_the_owning_module_is_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("ori.config._device._detect_host_timezone", lambda: None)
    monkeypatch.setattr("ori.config.Config.load", lambda *a, **k: None)


TESTS = Path(__file__).resolve().parent


_PACKAGE_NAMESPACE = "ori.config.__dict__"
#: The callables that write a mapping, and the keyword each takes it under.
_DICT_WRITERS = {"dict": "in_dict", "setitem": "dic"}


def _is_package(node: ast.AST, aliases: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in aliases
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "config"
        and isinstance(node.value, ast.Name)
        and node.value.id == "ori"
    )


def _is_package_dict(node: ast.AST, aliases: set[str], held: set[str]) -> bool:
    """``ori.config``'s namespace in any form a file can name statically.

    The string ``"ori.config.__dict__"``, ``ori.config.__dict__`` or
    ``vars(ori.config)`` under any alias of the package, or a variable assigned
    from one of those. A section module's own namespace is not the package's.
    """
    if isinstance(node, ast.Constant):
        return node.value == _PACKAGE_NAMESPACE
    if isinstance(node, ast.Name):
        return node.id in held
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return _is_package(node.value, aliases)
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "vars"
        and len(node.args) == 1
        and _is_package(node.args[0], aliases)
    )


def _package_aliases(tree: ast.Module) -> set[str]:
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases |= {
                a.asname for a in node.names if a.name == "ori.config" and a.asname
            }
        elif isinstance(node, ast.ImportFrom) and node.module == "ori":
            aliases |= {a.asname or a.name for a in node.names if a.name == "config"}
    return aliases


def _writer(node: ast.Call, writers: dict[str, str]) -> str | None:
    """The keyword the mapping goes under, if *node* calls a mapping writer."""
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in _DICT_WRITERS:
        return _DICT_WRITERS[func.attr]
    if isinstance(func, ast.Name):
        return writers.get(func.id)
    return None


def dict_patches(root: Path) -> list[str]:
    """Writes into ``ori.config``'s namespace that bypass its module class.

    ``patch.dict`` and ``setitem`` write the mapping directly, and a ``with``
    block restores it before the test ends, so neither the class nor a
    snapshot sees them. This scan covers every target it can name statically
    (see `_is_package_dict`), passed positionally or by keyword, through an
    alias of the writer too. A target computed at run time is outside it.
    """
    found = []
    for path in sorted(root.rglob("*.py")):
        if path == Path(__file__).resolve():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        aliases = _package_aliases(tree)
        held: set[str] = set()
        writers: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if not isinstance(target, ast.Name):
                    continue
                if _is_package_dict(node.value, aliases, held):
                    held.add(target.id)
                elif (
                    isinstance(node.value, ast.Attribute)
                    and node.value.attr in _DICT_WRITERS
                ):
                    writers[target.id] = _DICT_WRITERS[node.value.attr]
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            keyword = _writer(node, writers)
            if keyword is None:
                continue
            candidates = list(node.args[:1]) + [
                k.value for k in node.keywords if k.arg == keyword
            ]
            if any(_is_package_dict(c, aliases, held) for c in candidates):
                found.append(f"{path.relative_to(root.parent)}:{node.lineno}")
    return found


def test_no_test_patches_the_namespace_of_ori_config() -> None:
    found = dict_patches(TESTS)
    assert not found, (
        "patch each binding a caller reads, as tests/config_layout.py lists "
        "them, not ori.config's namespace: " + ", ".join(found)
    )


def test_the_namespace_scan_finds_each_spelling(tmp_path: Path) -> None:
    """Restored ``with`` blocks in a body and a fixture, and every target form."""
    (tmp_path / "test_x.py").write_text(
        "import pytest\n"
        "import ori.config\n"
        "import ori.config as cfg\n"
        "from ori import config as c2\n"
        "from unittest import mock\n"
        "from unittest.mock import patch\n"
        "pd = mock.patch.dict\n"
        "ns = vars(cfg)\n"
        "@pytest.fixture\n"
        "def held():\n"
        "    with mock.patch.dict(ori.config.__dict__, _parse_actions=None):\n"
        "        yield\n"
        "def test(monkeypatch, held):\n"
        "    with mock.patch.dict('ori.config.__dict__', _parse_actions=None):\n"
        "        pass\n"
        "    with patch.dict(in_dict='ori.config.__dict__', values={}):\n"
        "        pass\n"
        "    mock.patch.dict(vars(c2), {})\n"
        "    pd(ns, {})\n"
        "    monkeypatch.setitem(dic=cfg.__dict__, name='x', value=1)\n"
        "    monkeypatch.setitem(ns, 'x', 1)\n"
        "    mock.patch.dict(ori.config._device.__dict__, {})\n"
        "    mock.patch.dict('ori.config._device.__dict__', {})\n"
        "    monkeypatch.setitem(dict(), 'x', 1)\n"
    )
    assert len(dict_patches(tmp_path)) == 7, dict_patches(tmp_path)


class _ReachedError(Exception):
    pass


def _reached(*args: object, **kwargs: object) -> None:
    raise _ReachedError


EXAMPLE = TESTS.parent / "ori.linux.yaml.example"


def test_patching_every_named_binding_reaches_config_load(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refusal's advice works: Config.load calls what was patched."""
    for target in config_owners()["_parse_actions"]:
        monkeypatch.setattr(target, _reached)
    # Config.load reports a parser's exception as its own, with the cause kept.
    with pytest.raises(ori.config.ConfigValidationError) as refused:
        ori.config.Config.load(str(EXAMPLE))
    assert isinstance(refused.value.__cause__, _ReachedError)


def test_patching_only_where_it_is_defined_does_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Why the advice names callers: the defining module's binding is not read."""
    monkeypatch.setattr("ori.config._actions.parse_actions", _reached)
    ori.config.Config.load(str(EXAMPLE))
