# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""No test rebinds a name on ``ori.config`` itself.

``ori.config`` only re-exports; the code that calls a helper runs in the
section module that defines it. A patch on the re-export never reaches that
caller, so the test passes whether or not the behaviour it targets holds.
``tests/package_layout.py`` refuses every such rebinding while the suite runs,
and the conftest fails a test that rebound one through the module's dict.
These tests drive that guard through each spelling of a patch.
"""

from __future__ import annotations

import contextlib
import importlib
import os
import sys
import types
from collections import ChainMap
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, cast
from unittest import mock

import pytest

import ori.config
import ori.runtime
from tests.package_layout import (
    CONFIG,
    RUNTIME,
    ReexportRebindError,
    begin_phase,
    bindings,
    bindings_of,
    check_bindings,
    patched_runtime,
    rebound,
    take_problems,
)

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
    with mock.patch.dict(vars(cfg), {"datetime": vars(cfg)["datetime"]}):
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
            lambda mp: mp.setitem(vars(_device), "_detect_host_timezone", str),
            id="section-setitem",
        ),
        pytest.param(lambda mp: mp.setitem({}, "x", 1), id="other-mapping"),
        pytest.param(
            lambda mp: mp.delitem(vars(_device), "_detect_host_timezone"),
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
    """Why the advice names callers: the defining module's binding is not read.

    The suite refuses this partial patch as it is undone, so the test takes
    the refusal itself.
    """
    monkeypatch.setattr("ori.config._actions.parse_actions", _reached)
    ori.config.Config.load(str(EXAMPLE))
    monkeypatch.undo()
    assert take_problems() == [PARTIAL]


@pytest.mark.parametrize(
    "absent",
    [
        pytest.param(
            lambda mp: mp.setattr(cfg, "not_a_binding", 1, raising=False),
            id="raising-false",
        ),
        pytest.param(
            lambda mp: mock.patch.object(cfg, "not_a_binding", 1, create=True).start(),
            id="create-true",
        ),
        pytest.param(
            lambda mp: setattr(cfg, "not_a_binding", 1), id="plain-assignment"
        ),
    ],
)
def test_a_name_the_package_never_bound_is_refused(
    monkeypatch: pytest.MonkeyPatch, absent
) -> None:
    # mock's own cleanup after a refused create=True raises in turn, so the
    # refusal may arrive as the context of another AttributeError.
    try:
        with pytest.raises(AttributeError) as refused:
            absent(monkeypatch)
    finally:
        mock.patch.stopall()
    chain: BaseException | None = refused.value
    while chain is not None and not isinstance(chain, ReexportRebindError):
        chain = chain.__context__
    assert chain is not None and "does not bind not_a_binding" in str(chain)
    assert "not_a_binding" not in vars(cfg)


def test_the_import_system_still_binds_a_submodule_on_first_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delitem(sys.modules, "ori.config.installer", raising=False)
    monkeypatch.delattr(cfg, "installer", raising=False)
    imported = importlib.import_module("ori.config.installer")
    assert vars(cfg)["installer"] is imported
    monkeypatch.undo()
    assert take_problems() == []


def test_deleting_one_binding_of_a_shared_object_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delitem(vars(_device), "checked_device_id")
    monkeypatch.undo()
    assert take_problems() == [DEVICE_ID_PARTIAL]


PARTIAL = (
    "patched or deleted ori.config._actions.parse_actions but not "
    "ori.config._config.parse_actions; each is read by the code in its own "
    "module, so patch them all."
)
NEVER_BOUND = (
    "ori.runtime._startup never bound no_such, so binding it reaches no caller"
)
ON_PACKAGE = "ori.runtime._startup was rebound on its package"


def _fake_module() -> types.ModuleType:
    return types.ModuleType("fake")


@pytest.mark.parametrize(
    ("undone", "expected"),
    [
        pytest.param(
            lambda: mock.patch("ori.config._actions.parse_actions", _reached),
            PARTIAL,
            id="mock-patch",
        ),
        pytest.param(
            lambda: _context(
                lambda mp: mp.setattr("ori.config._actions.parse_actions", _reached)
            ),
            PARTIAL,
            id="monkeypatch-context",
        ),
        pytest.param(
            lambda: mock.patch("ori.runtime._startup.no_such", 1, create=True),
            NEVER_BOUND,
            id="create-true-on-a-private-module",
        ),
        pytest.param(
            lambda: _context(
                lambda mp: mp.setattr("ori.runtime._startup.no_such", 1, raising=False)
            ),
            NEVER_BOUND,
            id="raising-false-on-a-private-module",
        ),
        pytest.param(
            lambda: mock.patch.dict("ori.runtime._startup.__dict__", {"no_such": 1}),
            NEVER_BOUND,
            id="patch-dict-on-a-private-module",
        ),
        pytest.param(
            lambda: _context(
                lambda mp: mp.setattr(ori.runtime, "_startup", _fake_module())
            ),
            ON_PACKAGE,
            id="a-submodule-rebound-on-its-package",
        ),
    ],
)
def test_a_patch_undone_before_the_test_returns_is_still_checked(
    undone, expected: str
) -> None:
    with undone():
        pass
    [report] = take_problems()
    assert report.startswith(expected)


def test_a_patch_stopped_before_the_test_returns_is_still_checked() -> None:
    patcher = mock.patch("ori.config._actions.parse_actions", _reached)
    patcher.start()
    patcher.stop()
    assert take_problems() == [PARTIAL]


@contextlib.contextmanager
def _context(patch) -> Iterator[None]:
    with pytest.MonkeyPatch.context() as mp:
        patch(mp)
        yield


def test_every_binding_patched_together_unwinds_without_a_report() -> None:
    """An ExitStack undoes its patches one by one; only the first undo checks."""
    with patched_runtime("EXTERNAL_WATCHDOG_GPIO", 99):
        pass
    with mock.patch("ori.config._actions.parse_actions", _reached):
        with mock.patch("ori.config._config.parse_actions", _reached):
            pass
    assert take_problems() == []


def test_a_plain_assignment_is_checked_however_soon_it_is_undone() -> None:
    startup = importlib.import_module("ori.runtime._startup")
    original = _actions.parse_actions
    startup.no_such = 1  # type: ignore[attr-defined]
    del startup.no_such  # type: ignore[attr-defined]
    setattr(_actions, "parse_actions", _reached)
    setattr(_actions, "parse_actions", original)
    assert sorted(take_problems()) == sorted([NEVER_BOUND_REPORT, PARTIAL])


NEVER_BOUND_REPORT = (
    "ori.runtime._startup never bound no_such, so binding it reaches no caller. "
    "Patch each binding a caller reads, in the modules under ori/runtime/."
)


def test_a_write_to_a_namespace_is_checked_while_it_is_in_place() -> None:
    """A write straight into a namespace passes no class, so it is seen by the
    next check: one undone before then is the stated limit."""
    ori.runtime.__dict__["no_such"] = 1
    try:
        [report] = take_problems()
    finally:
        del ori.runtime.__dict__["no_such"]
    assert report.startswith("ori.runtime never bound no_such")
    assert take_problems() == []


def test_patching_every_binding_passes_in_any_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unrelated undos between the steps of one complete patch, nested blocks
    and patches stopped out of order are all a complete list of targets."""
    monkeypatch.setattr("ori.config._actions.parse_actions", _reached)
    with mock.patch.dict(os.environ, {"ORI_UNRELATED": "1"}):
        pass
    monkeypatch.setattr("ori.config._config.parse_actions", _reached)
    first = mock.patch("ori.config._actions.parse_actions", _reached)
    second = mock.patch("ori.config._config.parse_actions", _reached)
    first.start()
    second.start()
    first.stop()
    second.stop()
    assert take_problems() == []


def test_a_leftover_is_reported_once_and_then_held_as_the_start() -> None:
    """``begin_phase`` runs before each test: a binding left changed is
    reported against the next test only, not against every test after it."""
    original = _actions.parse_actions
    setattr(_actions, "parse_actions", _reached)
    try:
        assert begin_phase("Left") == [f"Left: {PARTIAL}"]
        assert begin_phase("Left") == []
    finally:
        setattr(_actions, "parse_actions", original)
    assert begin_phase("Left") == []
    # Which modules bind one object is kept, so the next partial is seen.
    with mock.patch("ori.config._config.parse_actions", _reached):
        pass
    [report] = take_problems()
    assert report.startswith("patched or deleted ori.config._config.parse_actions")


def test_a_complete_patch_left_in_place_hides_no_later_partial() -> None:
    """A complete patch a module-scope fixture holds, or an earlier test left,
    is where the next test starts; patching one of its bindings is partial."""
    every = [
        mock.patch(target, _reached) for target in bindings_of(_actions.parse_actions)
    ]
    for patcher in every:
        patcher.start()
    try:
        assert begin_phase("Left") == []
        with mock.patch("ori.config._config.parse_actions", _other):
            pass
        [report] = take_problems()
        assert report.startswith("patched or deleted ori.config._config.parse_actions")
    finally:
        for patcher in every:
            patcher.stop()
        begin_phase("")


def _other(*args: object, **kwargs: object) -> None:
    raise _ReachedError


def test_one_module_own_import_may_be_patched_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``os`` and ``datetime`` are tools from outside Ori: patching one
    module's binding of them fakes that module alone."""
    monkeypatch.setattr(_device, "os", mock.Mock())
    monkeypatch.setattr(_device, "datetime", mock.Mock())
    monkeypatch.undo()
    assert take_problems() == []


DEVICE_ID_PARTIAL = (
    "patched or deleted ori.config._device.checked_device_id but not "
    "ori.config._fields.checked_device_id; each is read by the code in its own "
    "module, so patch them all."
)


def test_equal_values_under_different_names_are_not_one_binding() -> None:
    """Numbers are grouped by name and identity: two equal constants can be one
    object, and patching one is not a partial patch of the other."""
    _constants = importlib.import_module("ori.runtime._constants")

    first = vars(_constants)["TIER_D_DRAIN_TIMEOUT"]
    assert first is vars(_constants)["EVIDENCE_SHUTDOWN_FLUSH_TIMEOUT_S"]
    for group in (*CONFIG.shared_bindings(), *RUNTIME.shared_bindings()):
        assert not {
            "ori.runtime._constants.TIER_D_DRAIN_TIMEOUT",
            "ori.runtime._constants.EVIDENCE_SHUTDOWN_FLUSH_TIMEOUT_S",
        } <= set(group)


def test_a_function_is_one_binding_under_every_local_name() -> None:
    assert any(
        {"ori.config._device._require_str", "ori.config._fields.require_str"}
        <= set(group)
        for group in CONFIG.shared_bindings()
    )


def test_a_module_named_like_a_submodule_is_not_one() -> None:
    impostor = types.ModuleType("ori.config.impostor")
    with pytest.raises(ReexportRebindError, match="does not bind impostor"):
        setattr(cfg, "impostor", impostor)


def test_release_restores_what_was_held_and_holding_twice_wraps_once() -> None:
    """The guard lasts one test session, so an embedding process gets its own."""
    from _pytest.monkeypatch import MonkeyPatch

    from tests import package_layout

    held = dict(package_layout._HELD)
    package_layout.release_reexports()
    try:
        assert type(ori.config) is held["module_classes"]["ori.config"]
        assert MonkeyPatch.setitem is held["setitem"]
        assert MonkeyPatch.delitem is held["delitem"]
        assert cast(Any, mock)._patch_dict._patch_dict is held["apply"]
        for name, original in held["module_classes"].items():
            assert type(sys.modules[name]) is original, name
    finally:
        package_layout.hold_reexports()
        package_layout.hold_reexports()
    assert package_layout._HELD["setitem"] is held["setitem"]
    assert type(ori.config).__name__ == "_ReexportsHeld"
    with pytest.raises(AssertionError, match=NAMESPACE_REFUSED):
        MonkeyPatch().setitem(vars(cfg), "x", 1)


def test_a_module_imported_on_first_use_is_checked_with_the_rest() -> None:
    """``ori.config.installer`` is imported on first use, after the guard is
    installed, and reads its own binding all the same."""
    from ori.config._document import read_config_bytes

    targets = bindings_of(read_config_bytes)
    assert "ori.config.installer.read_config_bytes" in targets
    with contextlib.ExitStack() as stack:
        for target in targets:
            if not target.startswith("ori.config.installer."):
                stack.enter_context(mock.patch(target, _reached))
    [report] = take_problems()
    assert report.endswith(
        "but not ori.config.installer.read_config_bytes; each is read by the code "
        "in its own module, so patch them all."
    )


def test_a_refused_namespace_write_is_not_reported_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refusal undoes the write; checking it as it is undone would report
    a rebinding the test never kept."""
    monkeypatch.setattr(_device, "_detect_host_timezone", str)
    with pytest.raises(AssertionError, match=NAMESPACE_REFUSED):
        mock.patch.dict("ori.config.__dict__", anchor_to_config=None).start()
    assert take_problems() == []


def test_a_problem_is_reported_once_per_test() -> None:
    """The call and its teardown are both checked; the second does not repeat
    what the first reported."""
    ori.runtime.__dict__["no_such"] = 1
    try:
        first, second = check_bindings(), check_bindings()
    finally:
        del ori.runtime.__dict__["no_such"]
        take_problems()
    assert len(first) == 1
    assert second == []


def test_a_binding_deleted_through_delattr_is_checked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(_device, "checked_device_id")
    monkeypatch.undo()
    assert take_problems() == [DEVICE_ID_PARTIAL]


def test_a_reexport_written_into_the_namespace_is_refused() -> None:
    original = vars(cfg)["anchor_to_config"]
    cfg.__dict__["anchor_to_config"] = _reached
    try:
        [report] = take_problems()
    finally:
        cfg.__dict__["anchor_to_config"] = original
        take_problems()
    assert REFUSED in report


def test_one_shared_object_is_one_group_wherever_it_comes_from() -> None:
    """A function, a logger, and a class from the other split package are each
    one object the runtime's modules read; stdlib tools are not."""
    groups = [set(group) for group in RUNTIME.shared_bindings()]
    for target in (
        "ori.runtime._health.now_ms",
        "ori.runtime._alerts.logger",
        "ori.runtime._services.Config",
    ):
        assert any(target in group for group in groups), target
    assert not any("ori.runtime._startup.asyncio" in group for group in groups)


def test_a_partial_override_of_a_complete_patch_is_checked() -> None:
    """A fixture's complete patch is where the call starts; the body replacing
    one of its bindings is partial, even when it restores it."""
    every = [
        mock.patch(target, _reached) for target in bindings_of(_actions.parse_actions)
    ]
    for patcher in every:
        patcher.start()
    try:
        assert begin_phase("In setup") == []
        with mock.patch("ori.config._config.parse_actions", _other):
            pass
        [report] = take_problems()
        assert report.startswith("patched or deleted ori.config._config.parse_actions")
    finally:
        for patcher in every:
            patcher.stop()
        begin_phase("")


def test_the_test_that_mends_a_leftover_split_is_not_blamed() -> None:
    original = _actions.parse_actions
    setattr(_actions, "parse_actions", _reached)
    try:
        assert begin_phase("Left") == [f"Left: {PARTIAL}"]
        with mock.patch("ori.config._config.parse_actions", _reached):
            pass
        assert take_problems() == []
    finally:
        setattr(_actions, "parse_actions", original)
        begin_phase("")


class _EqualToAll:
    def __eq__(self, other: object) -> bool:
        return True

    __hash__ = object.__hash__


def test_a_binding_is_compared_by_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_device, "checked_device_id", _EqualToAll())
    monkeypatch.undo()
    assert take_problems() == [DEVICE_ID_PARTIAL]


def test_a_partial_of_an_ori_function_is_ori_and_a_compiler_flag_is_no_binding() -> (
    None
):
    import functools

    from ori.utils.time_utils import now_ms
    from tests.package_layout import _is_ori

    assert _is_ori(functools.partial(now_ms))
    assert not _is_ori(functools.partial(print))
    for group in (*CONFIG.shared_bindings(), *RUNTIME.shared_bindings()):
        assert not any(target.endswith(".annotations") for target in group), group
