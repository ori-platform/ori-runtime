# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The bench latency proof stays runnable, and passes on an unloaded host."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from ori.reasoning.action_dispatcher import ActionDispatcher
from scripts import pi_dispatch_latency_proof as proof
from tests.waiting import latency_bounds_apply

# Past the post-commit bound (0.25 s), inside the reply ceiling (1 s).
STALL_S = 0.35


async def test_the_proof_runs_and_reports_every_bound(tmp_path: Path) -> None:
    report = await proof._prove(tmp_path, 3, notice_readings=0)
    assert report["inbound_messages_left_with_broker"] > 0
    for name in proof.CASES:
        first = report["tier_d"][name]["first_act_latency"]
        assert first["n"] == 3 and first["missed"] == 0
    assert set(report["tier_c_decisions"]) == {"executed"}, report["tier_c_decisions"]
    approvals = report["approved_tier_c_reply_to_act"]
    assert approvals["missed"] == 0
    after_commit = report["approved_tier_c_commit_to_act"]
    assert after_commit["n"] == report["tier_c_rounds"] > 0
    assert after_commit["missed"] == 0
    assert report["tier_c_rounds_one_approved_act"] == report["tier_c_rounds"]
    if latency_bounds_apply():
        assert report["pass"] is True, report
        for name in proof.CASES:
            first = report["tier_d"][name]["first_act_latency"]
            assert first["max_ms"] < proof.FIRST_ACT_BOUND_S * 1000
        assert approvals["max_ms"] < proof.TIER_C_TARGET_BOUND_S * 1000
        assert report["tier_c_target_met"] is True
        assert after_commit["max_ms"] < proof.COMMIT_TO_ACT_BOUND_S * 1000


async def test_a_stall_after_the_approval_commit_fails_the_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dispatch = ActionDispatcher._dispatch_admitted

    async def stalled(self: ActionDispatcher, *args: Any, **kwargs: Any) -> Any:
        await asyncio.sleep(STALL_S)
        return await dispatch(self, *args, **kwargs)

    monkeypatch.setattr(ActionDispatcher, "_dispatch_admitted", stalled)
    report = await proof._prove(tmp_path, 3, notice_readings=0)
    # The stall is a lower bound, which load only lengthens.
    assert report["approved_tier_c_commit_to_act"]["max_ms"] >= STALL_S * 1000
    assert report["pass"] is False
    if latency_bounds_apply():
        assert STALL_S > proof.COMMIT_TO_ACT_BOUND_S
        assert report["approved_tier_c_reply_to_act"]["max_ms"] < (
            proof.TIER_C_CEILING_BOUND_S * 1000
        )


async def test_a_safe_default_beside_the_approved_act_fails_the_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dispatch = ActionDispatcher._dispatch_admitted

    async def also_safe_default(
        self: ActionDispatcher, action: str, context: Any, *args: Any
    ) -> Any:
        result = await dispatch(self, action, context, *args)
        await self._executors["log_to_dashboard"]("log_to_dashboard", context)
        return result

    monkeypatch.setattr(ActionDispatcher, "_dispatch_admitted", also_safe_default)
    report = await proof._prove(tmp_path, 3, notice_readings=0)
    assert report["approved_tier_c_commit_to_act"]["missed"] == 0
    assert report["tier_c_rounds_one_approved_act"] == 0
    assert report["pass"] is False
