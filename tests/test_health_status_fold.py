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

from ori.runtime import OriRuntime
from ori.runtime._health_status import firmware_liveness_severity
from ori.runtime._health_status import fold_health_status as _fold_health_status


class _Scheduler:
    def __init__(
        self,
        *,
        critical: bool | None,
        undeclared: tuple[str, ...] | None = (),
        started: bool = True,
    ) -> None:
        self._critical = critical
        self._undeclared = undeclared
        self._started = started

    async def undeclared_device_ids(self) -> tuple[str, ...]:
        if self._undeclared is None:
            raise RuntimeError("registry unreadable")
        return self._undeclared

    def health(self, undeclared: frozenset[str] = frozenset()) -> dict[str, object]:
        if self._critical is None:
            return {"running": True, "started": self._started, "degraded": False}
        return {
            "running": True,
            "started": self._started,
            "degraded": True,
            "critical": self._critical,
        }


def _liveness(
    *,
    critical: bool | None,
    undeclared: tuple[str, ...] | None = (),
    started: bool = True,
) -> Callable[[OriRuntime], None]:
    return _set(
        "_firmware_liveness_scheduler",
        _Scheduler(critical=critical, undeclared=undeclared, started=started),
    )


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


def _heartbeat_clock_out_of_range(runtime: OriRuntime) -> None:
    runtime._runtime_node_heartbeat_publisher = SimpleNamespace(  # type: ignore[assignment]
        clock_out_of_range=True
    )


CONDITIONS: dict[str, tuple[str, Callable[[OriRuntime], None]]] = {
    "decision_record_lost": ("critical", _set("_decision_records_lost", lambda: 1)),
    "liveness_critical": ("critical", _liveness(critical=True)),
    "liveness_degraded": ("degraded", _liveness(critical=False)),
    "liveness_manifests_unlisted": (
        "critical",
        _liveness(critical=None, undeclared=None),
    ),
    "liveness_signing_domains_undeclared": (
        "degraded",
        _liveness(critical=None, undeclared=("fw-01",)),
    ),
    "liveness_starting": ("degraded", _liveness(critical=None, started=False)),
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
    "heartbeat_clock_out_of_range": ("degraded", _heartbeat_clock_out_of_range),
}
# The five liveness entries drive the one liveness branch.
BRANCHES = len(CONDITIONS) - 4


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
        # Every liveness entry sets the one scheduler.
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


def _parsed(method: object) -> ast.Module:
    return ast.parse(textwrap.dedent(inspect.getsource(method)))  # type: ignore[arg-type]


def _severity_appends(tree: ast.Module) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "append"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "severities"
    ]


def _severity_uses(tree: ast.Module) -> list[ast.Name]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and node.id == "severities"
    ]


def test_every_condition_branch_is_driven() -> None:
    """A condition added to the builder without a row here fails.

    The conditions are in `_health_severities`, which the builder calls; the
    builder itself appends nothing and only folds what it returns.
    """
    builder = _parsed(OriRuntime._build_health_snapshot)
    conditions = _parsed(OriRuntime._health_severities)
    appends = _severity_appends(conditions)
    uses = _severity_uses(conditions)
    # One declaration, one return, and every other use an append.
    assert len(uses) == len(appends) + 2, (
        "`severities` is read or written other than by `.append`, its "
        f"declaration and its return; found {len(uses) - len(appends) - 2} other use(s)"
    )
    # The builder takes the list once and folds it once, and adds nothing.
    assert _severity_appends(builder) == []
    assert len(_severity_uses(builder)) == 2
    assert len(appends) == BRANCHES, (
        f"the builder has {len(appends)} severity contributions and CONDITIONS "
        f"drives {BRANCHES}; add a row for the new condition"
    )
    # The liveness branch folds its own conditions: loop (critical or
    # degraded, two rows), unavailable, starting and an undeclared device.
    liveness = _severity_appends(_parsed(firmware_liveness_severity))
    rows = [name for name in CONDITIONS if name.startswith("liveness_")]
    assert len(liveness) == len(rows) - 1, (
        f"firmware_liveness_severity has {len(liveness)} conditions and "
        f"CONDITIONS drives {len(rows) - 1}; add a liveness row"
    )


@pytest.mark.parametrize(
    ("critical", "undeclared", "status"),
    [
        (False, None, "critical"),
        (True, ("fw-01",), "critical"),
        (False, ("fw-01",), "degraded"),
    ],
    ids=["degraded-loop+unlisted", "critical-loop+undeclared", "both-degraded"],
)
async def test_liveness_conditions_together_report_the_most_severe(
    critical: bool, undeclared: tuple[str, ...] | None, status: str
) -> None:
    runtime = _runtime()
    _liveness(critical=critical, undeclared=undeclared)(runtime)
    snapshot = await runtime._build_health_snapshot()
    assert snapshot["status"] == status


def test_only_the_fold_assigns_status_and_critical() -> None:
    """A condition that writes `status` directly can overwrite a worse one.

    Recognises subscript stores, `update`, `setdefault`, `__setitem__`, `|=`
    and reassignment of the builder's `snapshot` naming `status` or
    `critical`, in the builder and in `_health_severities`, the helper it
    passes the snapshot to. It does not follow the snapshot into another name
    or any other helper.
    """
    writes: list[tuple[int, str, str]] = []
    nodes = [
        node
        for method in (OriRuntime._build_health_snapshot, OriRuntime._health_severities)
        for node in ast.walk(_parsed(method))
    ]
    for node in nodes:
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
        "status and critical are assigned once, from fold_health_status; a "
        "condition contributes to `severities` instead. This guard reads the "
        "`snapshot` name in the builder and in `_health_severities` only. "
        f"Found: {writes}"
    )
    fold = [
        node
        for node in ast.walk(_parsed(OriRuntime._build_health_snapshot))
        if isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "status"
    ]
    assert len(fold) == 1 and ast.unparse(fold[0].value) == (
        "fold_health_status(severities)"
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
