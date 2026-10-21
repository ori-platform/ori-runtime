# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The snapshot's status is the most severe condition that holds.

Driven through the real `_build_health_snapshot`, so a condition that assigns
`status` instead of contributing to the fold is caught here, whatever order
the builder evaluates conditions in.
"""

from __future__ import annotations

import ast
import inspect
import itertools
import json
import pathlib
import textwrap
import types
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest

from ori.runtime import OriRuntime, _fold_health_status


class _Scheduler:
    def __init__(self, *, critical: bool) -> None:
        self._critical = critical

    def health(self) -> dict[str, object]:
        return {"running": True, "degraded": True, "critical": self._critical}


class _Commissioning:
    problems = ["declared_actuator_without_binding"]

    def health(self) -> dict[str, Any]:
        return {"zones": [], "problems": list(self.problems)}


class _Dispatcher:
    def get_policy_state_snapshot(self) -> dict[str, Any]:
        return {"available": False}

    def action_records(self) -> dict[str, Any]:
        return {}

    def action_records_degrade_health(self) -> bool:
        return True


class _Registry:
    def health_snapshot(self) -> dict[str, Any]:
        return {}

    def safety_zones(self) -> list[dict[str, Any]]:
        return [{"activation": "active", "protection_claim": "unprotected"}]


def _set(name: str, value: Any) -> Callable[[OriRuntime], None]:
    return lambda runtime: setattr(runtime, name, value)


async def _evidence_storage_fault() -> dict[str, Any]:
    return {"application_storage_fault": True}


class _RefusingClock:
    def refusing(self) -> bool:
        return True


def _signing_refused(runtime: OriRuntime) -> None:
    runtime._gateway_envelope_state = SimpleNamespace(  # type: ignore[assignment]
        signing_clock=_RefusingClock()
    )


CONDITIONS: dict[str, tuple[str, Callable[[OriRuntime], None]]] = {
    "decision_record_lost": ("critical", _set("_decision_records_lost", lambda: 1)),
    "liveness_critical": (
        "critical",
        _set("_firmware_liveness_scheduler", _Scheduler(critical=True)),
    ),
    "liveness_degraded": (
        "degraded",
        _set("_firmware_liveness_scheduler", _Scheduler(critical=False)),
    ),
    "commissioning_problem": (
        "degraded",
        _set("_commissioning_state", _Commissioning()),
    ),
    "active_zone_unprotected": ("degraded", _set("_safety_registry", _Registry())),
    "sensor_unconnected": ("degraded", _set("_unconnected_sensors", {"s1"})),
    "sensor_measurement_degraded": ("degraded", _set("_measurement_degraded", {"s1"})),
    "action_records_lost": ("degraded", _set("_records_lost_or_stalled", lambda: True)),
    "evidence_posture_problem": (
        "degraded",
        _set("_evidence_posture_problems", ("signing_unavailable",)),
    ),
    "community_skills_refused": (
        "degraded",
        _set("_community_skills_health", lambda: {"refused_skills": 1}),
    ),
    "config_unsigned_value_source": (
        "degraded",
        _set("_config_authority_health", lambda: {"unsigned_value_source": True}),
    ),
    "tier_c_records_degraded": ("degraded", _set("_dispatcher", _Dispatcher())),
    "evidence_application_storage_fault": (
        "degraded",
        _set("_evidence_health", _evidence_storage_fault),
    ),
    "gateway_signing_refused": ("degraded", _signing_refused),
}
# Both liveness entries drive the one liveness branch.
BRANCHES = len(CONDITIONS) - 1


def _runtime(*names: str) -> OriRuntime:
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._device_id = "dev-01"
    for name in names:
        CONDITIONS[name][1](runtime)
    return runtime


def _expected(*names: str) -> str:
    return (
        "critical" if any(CONDITIONS[n][0] == "critical" for n in names) else "degraded"
    )


async def test_nothing_wrong_is_healthy() -> None:
    snapshot = await _runtime()._build_health_snapshot()
    assert "status" not in snapshot
    assert snapshot["critical"] is False


@pytest.mark.parametrize("name", sorted(CONDITIONS))
async def test_each_condition_alone_reports_its_severity(name: str) -> None:
    snapshot = await _runtime(name)._build_health_snapshot()
    assert snapshot["status"] == CONDITIONS[name][0]
    assert snapshot["critical"] is (snapshot["status"] == "critical")


@pytest.mark.parametrize(
    "pair",
    [
        pair
        for pair in itertools.combinations(sorted(CONDITIONS), 2)
        # Both liveness entries set the one scheduler.
        if not all(name.startswith("liveness_") for name in pair)
    ],
    ids="+".join,
)
async def test_every_pair_reports_the_more_severe(pair: tuple[str, str]) -> None:
    snapshot = await _runtime(*pair)._build_health_snapshot()
    assert snapshot["status"] == _expected(*pair)
    assert snapshot["critical"] is (snapshot["status"] == "critical")


async def test_a_lost_decision_record_is_not_overwritten_by_later_conditions() -> None:
    names = ("decision_record_lost", "commissioning_problem", "active_zone_unprotected")
    snapshot = await _runtime(*names)._build_health_snapshot()
    assert snapshot["status"] == "critical"
    assert snapshot["critical"] is True


def test_the_fold_refuses_an_unknown_severity() -> None:
    assert _fold_health_status([]) is None
    assert _fold_health_status(["degraded", "critical", "degraded"]) == "critical"
    with pytest.raises(KeyError):
        _fold_health_status(["degraded", "warning"])
    with pytest.raises(KeyError):
        _fold_health_status(["fatal"])


def _named_keys(args: list[ast.expr], keywords: list[ast.keyword]) -> set[str]:
    """`status` or `critical` named as a constant, a keyword or a dict key."""
    named = {kw.arg for kw in keywords if kw.arg}
    for arg in args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            named.add(arg.value)
        if isinstance(arg, ast.Dict):
            named |= {
                key.value
                for key in arg.keys
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            }
    return named & {"status", "critical"}


def test_every_condition_branch_is_driven() -> None:
    """A condition added to the builder without a row here fails."""
    source = textwrap.dedent(inspect.getsource(OriRuntime._build_health_snapshot))
    appends = [
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "append"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "severities"
    ]
    uses = [
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Name) and node.id == "severities"
    ]
    # One declaration, one fold, and every other use an append.
    assert len(uses) == len(appends) + 2, (
        "`severities` is read or written other than by `.append` and the fold; "
        f"found {len(uses) - len(appends) - 2} other use(s)"
    )
    assert len(appends) == BRANCHES, (
        f"the builder has {len(appends)} severity contributions and CONDITIONS "
        f"drives {BRANCHES}; add a row for the new condition"
    )


def test_only_the_fold_assigns_status_and_critical() -> None:
    """A condition that writes `status` directly can overwrite a worse one.

    Recognises subscript stores, `update`, `setdefault`, `__setitem__`, `|=`
    and reassignment of the builder's `snapshot` naming `status` or
    `critical`. It does not follow the snapshot into another name or a helper
    it is passed to.
    """
    source = textwrap.dedent(inspect.getsource(OriRuntime._build_health_snapshot))
    writes: list[tuple[int, str, str]] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Assign | ast.AugAssign | ast.AnnAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "snapshot"
                    and isinstance(target.slice, ast.Constant)
                    and target.slice.value in ("status", "critical")
                ):
                    writes.append((node.lineno, target.slice.value, ast.unparse(node)))
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "snapshot"
            and node.func.attr in ("update", "setdefault", "__setitem__", "__ior__")
        ):
            for key in _named_keys(node.args, node.keywords):
                writes.append((node.lineno, key, ast.unparse(node)))
        if isinstance(node, ast.AugAssign | ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "snapshot"
            for target in (
                node.targets if isinstance(node, ast.Assign) else [node.target]
            )
        ):
            for key in _named_keys([node.value], []):
                writes.append((node.lineno, key, ast.unparse(node)))

    assert [(key, code) for _, key, code in sorted(writes)] == [
        ("status", "snapshot['status'] = status"),
        ("critical", "snapshot['critical'] = status == 'critical'"),
    ], (
        "status and critical are assigned once, from _fold_health_status; a "
        "condition contributes to `severities` instead. This guard reads the "
        f"builder's own `snapshot` name only. Found: {writes}"
    )
    fold = [
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "status"
    ]
    assert len(fold) == 1 and ast.unparse(fold[0].value) == (
        "_fold_health_status(severities)"
    ), "the builder's `status` comes from the fold alone"


HEALTH_V4 = json.loads(
    (
        pathlib.Path(__file__).resolve().parent
        / "vectors"
        / "runtime_health"
        / "health-vectors-v4.json"
    ).read_text()
)


def test_the_storage_fault_folds_at_runtime_health_v4s_severity() -> None:
    """The one v4 condition this v3 snapshot carries, at the corpus's severity."""
    assert (
        CONDITIONS["evidence_application_storage_fault"][0]
        == HEALTH_V4["conditions"]["evidence_application_storage_fault"]
    )


class _StorageFaultAttestor:
    available = True
    public_key_hex = ""
    action_event_type = ""
    anchor = None

    def __init__(self, raised: bool) -> None:
        self.application_storage_fault = raised

    async def chain_head_hash(self) -> None:
        return None

    async def pending_export_count(self) -> None:
        return None

    async def awaiting_receipt(self, _now: int) -> None:
        return None

    async def ingest_refusal_summary(self) -> None:
        return None


@pytest.mark.parametrize(
    "enabled, available, raised, reported",
    [
        (True, True, True, True),
        (True, True, False, False),
        # runtime-health/v4: false while evidence is disabled or not yet open.
        (False, True, True, False),
        (True, False, True, False),
    ],
)
async def test_the_evidence_block_reports_the_storage_fault_signal(
    enabled: bool, available: bool, raised: bool, reported: bool
) -> None:
    runtime = object.__new__(OriRuntime)
    setattr(
        runtime,
        "_config",
        types.SimpleNamespace(evidence=types.SimpleNamespace(enabled=enabled)),
    )
    runtime._state_store = None
    runtime._evidence_inbound_subscriber = None
    attestor = _StorageFaultAttestor(raised)
    attestor.available = available
    setattr(runtime, "_evidence_attestor", attestor)

    health = await runtime._evidence_health()

    assert health["application_storage_fault"] is reported
