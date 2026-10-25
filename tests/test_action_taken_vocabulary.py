# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""What ``action_taken`` says when no action was taken, and who may not say it."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from ori.network.events import ActionResult
from ori.reasoning import action_taken
from ori.reasoning.action_registry import ACTION_REGISTRY
from ori.reasoning.tier_c_admission import DECISION_STATES
from ori.skills.loader import SkillValidationError
from ori.state.store import StateStore
from tests import action_taken_guard
from tests.test_skill_loader import _first_party_loader, _write_skill_yaml


@pytest.mark.parametrize(
    ("executed", "taken", "breaks"),
    [
        (True, "trip_relay", False),
        (True, "rejected_unrecorded", False),
        (True, "suppressed", True),
        (False, "", False),
        (False, "refused_unknown_tier", False),
        (False, "dispatch_outcome_unknown", False),
        (False, "approval_expired_undispatched_unrecorded", False),
        (False, "proposal_not_committed", False),
        (False, "log_to_dashboard", True),
    ],
)
def test_the_suite_guard_holds_rows_to_the_vocabulary(
    executed: bool, taken: str, breaks: bool
) -> None:
    assert (action_taken_guard.violation(executed, taken) is not None) is breaks


async def test_the_suite_guard_sees_a_row_the_store_writes(tmp_path: Path) -> None:
    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    try:
        await store.log_action(
            ActionResult(
                action_name="log_to_dashboard",
                tier="A",
                executed=False,
                approved=None,
                action_taken="log_to_dashboard",
                timestamp=1,
            ),
            "t",
            record_key="k",
        )
    finally:
        await store.close()
    assert action_taken_guard.drain() == [
        "log_to_dashboard: a row that did not execute names unreserved "
        "'log_to_dashboard'"
    ]


def test_every_tier_c_decision_state_is_reserved() -> None:
    assert [s for s in DECISION_STATES if not action_taken.is_reserved(s)] == []


def test_no_registered_action_carries_a_reserved_name() -> None:
    assert [name for name in ACTION_REGISTRY if action_taken.is_reserved(name)] == []


def _skill(tmp_path: Path, *, available: str, safe_default: str = "") -> Path:
    safe = f"\n            safe_default_action: {safe_default}" if safe_default else ""
    skill_dir = tmp_path / "namer"
    _write_skill_yaml(
        skill_dir,
        f"""\
        name: namer
        version: 0.1.0
        author: test
        signature: bundled
        sensors_required:
          - type: current_clamp
            protocol: i2c
        triggers:
          - name: over_threshold
            condition: "value > 5.0"
            cooldown_seconds: 10
            action_tier: A{safe}
        actions:
          available:
            - name: {available}
              tier: A
          defaults:
            over_threshold: [{available}]
        """,
    )
    return skill_dir


_RESERVED = [
    "coalesced",
    "suppressed",
    "no_executor",
    "not_performed",
    "refused_anything",
    "rejected_unrecorded",
    "Coalesced",
]


@pytest.mark.parametrize("name", _RESERVED)
def test_a_skill_cannot_declare_a_reserved_action(tmp_path: Path, name: str) -> None:
    with pytest.raises(SkillValidationError, match=r"'namer'.*no action was taken"):
        _first_party_loader().load_one(_skill(tmp_path, available=name))


@pytest.mark.parametrize("name", _RESERVED)
def test_a_skill_cannot_name_a_reserved_safe_default(tmp_path: Path, name: str) -> None:
    skill_dir = _skill(tmp_path, available="note_owner", safe_default=name)
    with pytest.raises(SkillValidationError, match=r"'namer'.*no action was taken"):
        _first_party_loader().load_one(skill_dir)


@pytest.mark.parametrize("name", ["note_owner", "coalesce", "unrefused", "refused"])
def test_a_name_near_a_marker_is_the_skill_s_own(tmp_path: Path, name: str) -> None:
    skill = _first_party_loader().load_one(_skill(tmp_path, available=name))
    assert skill is not None and skill.name == "namer"


async def test_a_safe_default_that_raises_is_not_recorded_as_taken() -> None:
    from ori.reasoning.action_dispatcher import ActionDispatcher

    dispatcher = ActionDispatcher(config={})

    async def broken(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("executor fault")

    dispatcher._execute_immediately = broken  # type: ignore[method-assign]
    outcome = await dispatcher._resolve_failed_approval(
        "trip_relay", "C", cast(Any, object()), "note_owner", "p-1"
    )
    assert (outcome.executed, outcome.action_taken) == (False, "")


_SESSION_PROBE = """
import asyncio

import pytest

from ori.network.events import ActionResult
from ori.state.store import StateStore


def _write(path, taken, key):
    async def write():
        store = StateStore(str(path))
        await store.open()
        try:
            await store.log_action(
                ActionResult(
                    action_name="note_owner",
                    tier="A",
                    executed=False,
                    approved=None,
                    action_taken=taken,
                    timestamp=1,
                ),
                "t",
                record_key=key,
            )
        finally:
            await store.close()

    asyncio.run(write())


@pytest.fixture(scope="session")
def session_rows(tmp_path_factory):
    _write(tmp_path_factory.mktemp("setup") / "s.db", {setup!r}, "setup")
    yield
    _write(tmp_path_factory.mktemp("finalizer") / "f.db", {finalizer!r}, "finalizer")


def test_passes(session_rows):
    pass
"""


@pytest.mark.parametrize("xdist", [False, True], ids=["serial", "xdist"])
@pytest.mark.parametrize(
    ("setup", "finalizer", "fails"),
    [
        ("note_owner", "", True),
        ("", "note_owner", True),
        ("", "refused_policy", False),
    ],
    ids=["session-setup", "session-finalizer", "valid-rows"],
)
def test_a_session_fixture_row_outside_the_vocabulary_fails_the_run(
    tmp_path: Path, setup: str, finalizer: str, fails: bool, xdist: bool
) -> None:
    from tests.test_patch_guard_reports import _run_probe

    probe = _SESSION_PROBE.format(setup=setup, finalizer=finalizer)
    run = _run_probe(tmp_path, probe, xdist=xdist, outer=False)
    output = run.stdout + run.stderr
    if not fails:
        assert run.returncode == pytest.ExitCode.OK, output
        return
    assert run.returncode == pytest.ExitCode.TESTS_FAILED, output
    assert "names unreserved 'note_owner'" in output, output


async def test_a_write_the_store_refuses_is_not_held(tmp_path: Path) -> None:
    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    try:
        with pytest.raises(ValueError, match="record_key"):
            await store.log_action(
                ActionResult(
                    action_name="note_owner",
                    tier="A",
                    executed=False,
                    approved=None,
                    action_taken="note_owner",
                    timestamp=1,
                ),
                "t",
                record_key="",
            )
    finally:
        await store.close()
    assert action_taken_guard.drain() == []


_REPORT_PROBE = """
import asyncio
import itertools

import pytest

from ori.network.events import ActionResult
from ori.state.store import StateStore

_keys = itertools.count()


def _write(tmp_path, taken):
    async def write():
        store = StateStore(str(tmp_path / f"{{next(_keys)}}.db"))
        await store.open()
        try:
            await store.log_action(
                ActionResult(
                    action_name="note_owner",
                    tier="A",
                    executed=False,
                    approved=None,
                    action_taken=taken,
                    timestamp=1,
                ),
                "t",
                record_key=f"key-{{next(_keys)}}",
            )
        finally:
            await store.close()

    asyncio.run(write())


@pytest.fixture
def in_setup(tmp_path):
    _write(tmp_path, {taken!r})
    yield


@pytest.fixture
def in_teardown(tmp_path):
    yield
    _write(tmp_path, {taken!r})


@pytest.mark.xfail
def test_xfail_body(tmp_path):
    _write(tmp_path, {taken!r})
    assert False


@pytest.mark.xfail(strict=True)
def test_strict_xfail_body(tmp_path):
    _write(tmp_path, {taken!r})
    assert False


@pytest.mark.xfail
def test_xfail_setup(in_setup):
    assert False


@pytest.mark.xfail
def test_xfail_teardown(in_teardown):
    assert False


def test_skipped_body(tmp_path):
    _write(tmp_path, {taken!r})
    pytest.skip("skipped after the write")
"""


@pytest.mark.parametrize("xdist", [False, True], ids=["serial", "xdist"])
def test_no_outcome_absorbs_a_row_outside_the_vocabulary(
    tmp_path: Path, xdist: bool
) -> None:
    """Enforced on the finished report: xfail, strict or not, and skip included."""
    from tests.test_patch_guard_reports import _run_probe

    run = _run_probe(
        tmp_path, _REPORT_PROBE.format(taken="note_owner"), xdist=xdist, outer=False
    )
    output = run.stdout + run.stderr
    assert run.returncode == pytest.ExitCode.TESTS_FAILED, output
    for name in (
        "test_xfail_body",
        "test_strict_xfail_body",
        "test_xfail_setup",
        "test_xfail_teardown",
        "test_skipped_body",
    ):
        assert any(
            line.startswith(("FAILED", "ERROR")) and f"::{name}" in line
            for line in output.splitlines()
        ), (name, output)


def test_a_valid_row_keeps_its_expected_outcome(tmp_path: Path) -> None:
    from tests.test_patch_guard_reports import _run_probe

    run = _run_probe(tmp_path, _REPORT_PROBE.format(taken=""), outer=False)
    output = run.stdout + run.stderr
    assert run.returncode == pytest.ExitCode.OK, output
    assert "4 xfailed" in output and "1 skipped" in output, output
