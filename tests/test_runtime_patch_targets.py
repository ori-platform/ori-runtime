# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A test patches every binding the runtime's code reads, never ``ori.runtime``.

``ori.runtime`` only re-exports. ``OriRuntime`` is composed from one class per
domain, each in a private module that imports what it calls by value, so a
name such as ``now_ms`` is read through a binding in every module that uses
it. A patch on the re-export reaches none of them, and a patch on one module
reaches only the methods defined there; either way the test passes whether or
not the behaviour it targets holds. ``tests/package_layout.py`` refuses every
rebinding of a re-export while the suite runs, and ``runtime_bindings`` lists
the bindings a patch must reach. These tests drive both.
"""

from __future__ import annotations

import importlib
from typing import Any
from unittest import mock

import pytest

import ori.runtime
from ori.utils import time_utils
from tests.package_layout import (
    ReexportRebindError,
    bindings,
    patch_runtime,
    patched_runtime,
    rebound,
    runtime_bindings,
    runtime_owners,
)

REFUSED = "is a re-export; rebinding it reaches no caller"
NAMESPACE_REFUSED = "namespace holds re-exports; writing it reaches no caller"


def test_the_guard_is_installed() -> None:
    assert type(ori.runtime).__name__ == "_ReexportsHeld"


def test_every_export_has_an_owner() -> None:
    owners = runtime_owners()
    assert set(owners) == set(ori.runtime.__all__)
    for name, where in owners.items():
        assert where, name
        assert all(target.startswith("ori.runtime._") for target in where), where


@pytest.mark.parametrize(
    "rebind",
    [
        pytest.param(
            lambda mp: mp.setattr("ori.runtime.OriRuntime", None), id="setattr-string"
        ),
        pytest.param(
            lambda mp: mp.setattr(ori.runtime, "main", None), id="setattr-object"
        ),
        pytest.param(
            lambda mp: mp.setattr(
                importlib.import_module("ori.runtime"), "adapter_connect_config", None
            ),
            id="setattr-import-module",
        ),
        pytest.param(
            lambda mp: mp.delattr("ori.runtime.measurement_notice_stage_due"),
            id="delattr-string",
        ),
        pytest.param(
            lambda mp: setattr(ori.runtime, "MEASUREMENT_WINDOWS_TO_RECOVER", 1),
            id="assignment",
        ),
        pytest.param(
            lambda mp: mock.patch("ori.runtime.OriRuntime").start(), id="mock-patch"
        ),
        pytest.param(
            lambda mp: mock.patch.object(ori.runtime, "main").start(),
            id="mock-patch-object",
        ),
        pytest.param(
            lambda mp: mock.patch.multiple(
                "ori.runtime", EVIDENCE_SHUTDOWN_FLUSH_TIMEOUT_S=0
            ).start(),
            id="mock-patch-multiple",
        ),
    ],
)
def test_every_attribute_spelling_is_refused(
    monkeypatch: pytest.MonkeyPatch, rebind: Any
) -> None:
    before = bindings()
    try:
        with pytest.raises(ReexportRebindError, match=REFUSED) as refused:
            rebind(monkeypatch)
    finally:
        mock.patch.stopall()
    assert "Patch each binding a caller reads instead: ori.runtime._" in str(
        refused.value
    )
    assert rebound(before) == []


@pytest.mark.parametrize(
    "write",
    [
        pytest.param(
            lambda mp: mock.patch.dict("ori.runtime.__dict__", main=None).start(),
            id="patch-dict-string",
        ),
        pytest.param(
            lambda mp: mp.setitem(vars(ori.runtime), "main", None), id="setitem"
        ),
        pytest.param(lambda mp: mp.delitem(vars(ori.runtime), "main"), id="delitem"),
    ],
)
def test_every_namespace_write_is_refused(
    monkeypatch: pytest.MonkeyPatch, write: Any
) -> None:
    before = bindings()
    try:
        with pytest.raises(AssertionError, match=NAMESPACE_REFUSED):
            write(monkeypatch)
    finally:
        mock.patch.stopall()
    assert rebound(before) == []


def test_a_write_into_the_module_dict_is_found() -> None:
    before = bindings()
    namespace: dict[str, Any] = ori.runtime.__dict__
    original = namespace["main"]
    namespace["main"] = None
    try:
        problems = rebound(before)
    finally:
        namespace["main"] = original
    where = runtime_owners()["main"]
    assert "ori.runtime._main.main" in where
    assert problems == [
        "ori.runtime.main is a re-export; rebinding it reaches no caller. Patch "
        f"each binding a caller reads instead: {', '.join(where)}."
    ]
    assert rebound(before) == []


def test_a_name_the_runtime_only_imported_is_not_on_the_package() -> None:
    """Patching ``ori.runtime.now_ms`` fails loudly instead of reaching nothing."""
    with pytest.raises(AttributeError):
        mock.patch("ori.runtime.now_ms", lambda: 0).start()
    mock.patch.stopall()


def test_runtime_bindings_lists_every_module_that_reads_the_clock() -> None:
    targets = runtime_bindings("now_ms")
    readers = {
        module.__name__
        for module in importlib.import_module("tests.package_layout").RUNTIME.modules()
        if vars(module).get("now_ms") is time_utils.now_ms
    }
    assert {target.rsplit(".", 1)[0] for target in targets} == readers
    assert len(targets) > 3, targets


def test_a_constant_is_listed_by_name_only() -> None:
    """Equal numbers can be one object; a constant is never matched by identity."""
    targets = runtime_bindings("READ_FAILURE_LOG_INTERVAL_S")
    assert targets == (
        "ori.runtime._constants.READ_FAILURE_LOG_INTERVAL_S",
        "ori.runtime._sensors.READ_FAILURE_LOG_INTERVAL_S",
    )


class _ReachedError(Exception):
    pass


def _reached(*_args: object, **_kwargs: object) -> bool:
    raise _ReachedError


def _development() -> Any:
    from types import SimpleNamespace

    return SimpleNamespace(
        device=SimpleNamespace(deployment_profile="development"), security={}
    )


def test_patching_every_binding_reaches_the_capability_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The advice works: the capability check calls what was patched."""
    from ori.runtime._capabilities import validate_required_runtime_capabilities

    patch_runtime(monkeypatch, "requires_production_posture", _reached)
    with pytest.raises(_ReachedError):
        validate_required_runtime_capabilities(_development(), "ori.yaml")


def test_patching_only_where_it_is_defined_does_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Why the advice names callers: the defining module's binding is not read."""
    from ori.runtime._capabilities import validate_required_runtime_capabilities

    monkeypatch.setattr("ori.config._posture.requires_production_posture", _reached)
    validate_required_runtime_capabilities(_development(), "ori.yaml")


def test_patched_runtime_hands_every_binding_one_mock() -> None:
    with patched_runtime("now_ms", return_value=7) as clock:
        for target in runtime_bindings("now_ms"):
            module, name = target.rsplit(".", 1)
            assert getattr(importlib.import_module(module), name) is clock
    for target in runtime_bindings("now_ms"):
        module, name = target.rsplit(".", 1)
        assert getattr(importlib.import_module(module), name) is time_utils.now_ms


def test_patching_a_method_on_the_class_is_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("ori.runtime.OriRuntime._watchdog_loop", _reached)
    monkeypatch.setattr(ori.runtime.OriRuntime, "_heartbeat_loop", _reached)
