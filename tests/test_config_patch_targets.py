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

import importlib
from collections import ChainMap
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast
from unittest import mock

import pytest

import ori.config
from tests.config_layout import ReexportRebindError, bindings, bindings_of, rebound

REFUSED = "is a re-export; rebinding it reaches no caller"


def test_the_guard_is_installed() -> None:
    assert type(ori.config).__name__ == "_ReexportsHeld"


@pytest.mark.parametrize(
    "rebind",
    [
        pytest.param(
            lambda mp: mp.setattr("ori.config.anchor_to_config", None),
            id="setattr-string",
        ),
        pytest.param(
            # A string target takes its value through ``name``.
            lambda mp: mp.setattr(target="ori.config.read_config_document", name=None),
            id="setattr-keyword",
        ),
        pytest.param(
            lambda mp: mp.setattr(ori.config, "requires_production_posture", None),
            id="setattr-object",
        ),
        pytest.param(
            lambda mp: mp.setattr(
                ori.config, name="hardened_posture_declared", value=None
            ),
            id="setattr-object-keyword",
        ),
        pytest.param(
            lambda mp: mp.setattr("ori.config." + "config_env_placeholders", None),
            id="setattr-concatenated",
        ),
        pytest.param(
            lambda mp: mp.setattr(
                importlib.import_module("ori.config"), "Config", None
            ),
            id="setattr-import-module",
        ),
        pytest.param(
            lambda mp: mp.delattr("ori.config.SensorConfig"), id="delattr-string"
        ),
        pytest.param(
            lambda mp: setattr(ori.config, "SKILL_NAME_RE", None), id="assignment"
        ),
        pytest.param(
            lambda mp: mock.patch("ori.config.Config").start(),
            id="mock-patch",
        ),
        pytest.param(
            lambda mp: mock.patch.object(ori.config, "ConfigValidationError").start(),
            id="mock-patch-object",
        ),
        pytest.param(
            lambda mp: mock.patch.multiple(
                "ori.config", MAX_SKILL_NAME_LENGTH=0
            ).start(),
            id="mock-patch-multiple",
        ),
    ],
)
def test_every_attribute_spelling_is_refused(
    monkeypatch: pytest.MonkeyPatch, rebind
) -> None:
    before = bindings()
    try:
        with pytest.raises(ReexportRebindError, match=REFUSED) as refused:
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
    """A plain dict write passes the class and the writer guards; the snapshot
    catches it when it persists to the end of the test."""
    before = bindings()
    namespace: dict[str, Any] = ori.config.__dict__
    original = namespace["anchor_to_config"]
    namespace["anchor_to_config"] = None
    try:
        problems = rebound(before)
    finally:
        namespace["anchor_to_config"] = original
    assert problems == [
        "ori.config.anchor_to_config is a re-export; rebinding it reaches no "
        "caller. Patch each binding a caller reads instead: "
        "ori.config._config.anchor_to_config, ori.config._database.anchor_to_config."
    ]
    assert rebound(before) == []


def test_patching_the_owning_module_is_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("ori.config._device._detect_host_timezone", lambda: None)
    monkeypatch.setattr("ori.config.Config.load", lambda *a, **k: None)


TESTS = Path(__file__).resolve().parent
NAMESPACE_REFUSED = "namespace holds re-exports; writing it reaches no caller"
cfg = ori.config
_actions = importlib.import_module("ori.config._actions")
_device = importlib.import_module("ori.config._device")
root = importlib.import_module("ori")


def _delitem_in_a_fixture(mp: pytest.MonkeyPatch) -> None:
    def held():
        mp.delitem(cfg.__dict__, "anchor_to_config")
        yield

    next(held())


def _annotated() -> None:
    ns: Mapping[str, object] = vars(cfg)
    with mock.patch.dict(ns, {}):
        pass


def _chained() -> None:
    a = b = vars(cfg)
    with mock.patch.dict(b, {}):
        pass
    del a


def _unpacked() -> None:
    ns, _ = vars(cfg), None
    with mock.patch.dict(ns, {}):
        pass


def _writer_alias_of_alias() -> None:
    pd = mock.patch.dict
    pd2 = pd
    with pd2("ori.config.__dict__", {}):
        pass


def _root_alias() -> None:
    with mock.patch.dict(vars(root.config), {}):
        pass


def _in_a_fixture_like_generator() -> None:
    def held():
        with mock.patch.dict("ori.config.__dict__", anchor_to_config=None):
            yield

    next(held())


@pytest.mark.parametrize(
    "write",
    [
        pytest.param(
            lambda mp: mock.patch.dict(
                "ori.config.__dict__", anchor_to_config=None
            ).start(),
            id="string-target",
        ),
        pytest.param(
            lambda mp: mock.patch.dict(in_dict="ori.config.__dict__").start(),
            id="keyword-string",
        ),
        pytest.param(
            lambda mp: mock.patch.dict(cfg.__dict__, {}).start(), id="attribute"
        ),
        pytest.param(lambda mp: _annotated(), id="annotated-assignment"),
        pytest.param(lambda mp: _chained(), id="chained-assignment"),
        pytest.param(lambda mp: _unpacked(), id="unpacked-assignment"),
        pytest.param(lambda mp: _writer_alias_of_alias(), id="writer-alias-chain"),
        pytest.param(lambda mp: _root_alias(), id="root-import-alias"),
        pytest.param(lambda mp: _in_a_fixture_like_generator(), id="generator"),
        pytest.param(
            lambda mp: mp.setitem(vars(cfg), "anchor_to_config", None),
            id="setitem",
        ),
        pytest.param(
            lambda mp: mp.setitem(dic=cfg.__dict__, name="x", value=1),
            id="setitem-keyword",
        ),
        pytest.param(
            lambda mp: mp.delitem(vars(cfg), "anchor_to_config"), id="delitem"
        ),
        pytest.param(_delitem_in_a_fixture, id="delitem-fixture"),
    ],
)
def test_every_namespace_write_is_refused_by_identity(
    monkeypatch: pytest.MonkeyPatch, write
) -> None:
    before = bindings()
    try:
        with pytest.raises(AssertionError, match=NAMESPACE_REFUSED):
            write(monkeypatch)
    finally:
        mock.patch.stopall()
    assert rebound(before) == []
    assert "x" not in vars(ori.config)


def _reassigned() -> None:
    ns = vars(cfg)
    ns = {}
    with mock.patch.dict(ns, {"a": 1}):
        pass


def _shadowed(cfg: object) -> None:
    with mock.patch.dict(vars(cfg), {"a": 1}):
        pass


@pytest.mark.parametrize(
    "write",
    [
        pytest.param(lambda mp: _reassigned(), id="reassigned-to-a-dict"),
        pytest.param(
            lambda mp: _shadowed(importlib.import_module("ori.config._device")),
            id="parameter-shadows-the-alias",
        ),
        pytest.param(
            lambda mp: mock.patch.dict("ori.config._device.__dict__", {}).start(),
            id="section-namespace",
        ),
        pytest.param(
            lambda mp: mp.setitem(vars(_device), "x", 1), id="section-setitem"
        ),
        pytest.param(lambda mp: mp.setitem({}, "x", 1), id="other-mapping"),
        pytest.param(
            lambda mp: mp.delitem(vars(_device), "logger"),
            id="section-delitem",
        ),
        # The stated limit: a view delegating to the namespace is another
        # mapping, so it is not recognised.
        pytest.param(
            lambda mp: mock.patch.dict(ChainMap(cfg.__dict__), {}).start(),
            id="delegating-view",
        ),
    ],
)
def test_other_mappings_are_allowed(monkeypatch: pytest.MonkeyPatch, write) -> None:
    try:
        write(monkeypatch)
    finally:
        mock.patch.stopall()


class _ReachedError(Exception):
    pass


def _reached(*args: object, **kwargs: object) -> None:
    raise _ReachedError


EXAMPLE = TESTS.parent / "ori.linux.yaml.example"


def test_patching_every_named_binding_reaches_config_load(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refusal's advice works: Config.load calls what was patched."""
    for target in bindings_of(_actions.parse_actions):
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


def test_release_restores_what_was_held_and_holding_twice_wraps_once() -> None:
    """The guard lasts one test session, so an embedding process gets its own."""
    from _pytest.monkeypatch import MonkeyPatch

    from tests import config_layout

    held = dict(config_layout._HELD)
    config_layout.release_reexports()
    try:
        assert type(ori.config) is held["module_class"]
        assert MonkeyPatch.setitem is held["setitem"]
        assert MonkeyPatch.delitem is held["delitem"]
        assert cast(Any, mock)._patch_dict._patch_dict is held["apply"]
    finally:
        config_layout.hold_reexports()
        config_layout.hold_reexports()
    assert config_layout._HELD["setitem"] is held["setitem"]
    assert type(ori.config).__name__ == "_ReexportsHeld"
    with pytest.raises(AssertionError, match=NAMESPACE_REFUSED):
        MonkeyPatch().setitem(vars(cfg), "x", 1)
