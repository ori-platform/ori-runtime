# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The runtime's health export never reads as the v2.5.0 encoding.

gateway-api/v2's health transition reads an unmarked export whose members all
lie in v2.5.0's set as v2.5.0's snapshot, where the absence of `critical` and
`status` means healthy. That is safe only while every later release writes
`critical` always, as a JSON boolean, and carries a member v2.5.0 never sent.
The baselines are the exports v2.5.0 and e4ba3e92 produce, vendored from
ori-specs; this holds the current builder to them, healthy and under every
health condition.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.test_health_status_fold import CONDITIONS, _runtime

BASELINES = json.loads(
    (
        Path(__file__).parent
        / "vectors"
        / "gateway_api"
        / "health-transition-baselines-v2.json"
    ).read_text(encoding="utf-8")
)
#: Members v2.5.0 may send only while a condition holds.
_V250_CONDITIONAL = {"status", "critical", "degradation_reasons", "safety_zones"}
#: A member may be null where its subsystem is not built yet.
_NULLABLE = {"safety"}


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    return {str: "string", list: "array", dict: "object"}[type(value)]


async def _snapshot(*conditions: str) -> dict[str, Any]:
    return await _runtime(*conditions)._build_health_snapshot()


@pytest.mark.parametrize("conditions", [(), *[(name,) for name in CONDITIONS]])
async def test_every_snapshot_writes_critical_and_leaves_the_v2_5_0_set(
    conditions: tuple[str, ...],
) -> None:
    snapshot = json.loads(json.dumps(await _snapshot(*conditions), default=str))
    assert type(snapshot.get("critical")) is bool
    v250 = set(BASELINES["v2.5.0"]) | _V250_CONDITIONAL
    assert not set(snapshot) <= v250, "the export would read as v2.5.0's encoding"


async def test_the_export_keeps_every_baseline_member_at_its_type() -> None:
    snapshot = json.loads(json.dumps(await _snapshot(), default=str))
    for member, value in BASELINES["e4ba3e92"].items():
        assert member in snapshot, member
        expected = _json_type(value)
        actual = _json_type(snapshot[member])
        if member in _NULLABLE and "null" in (expected, actual):
            continue
        assert actual == expected, (member, actual, expected)
