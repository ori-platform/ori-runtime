# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The bench latency proof stays runnable, and passes on an unloaded host."""

from __future__ import annotations

from pathlib import Path

from scripts import pi_dispatch_latency_proof as proof


async def test_the_proof_runs_and_reports_every_bound(tmp_path: Path) -> None:
    report = await proof._prove(tmp_path, 3, notice_readings=0)
    assert report["pass"] is True, report
    assert report["inbound_messages_left_with_broker"] > 0
    for name in proof.CASES:
        first = report["tier_d"][name]["first_act_latency"]
        assert first["n"] == 3 and first["missed"] == 0
        assert first["max_ms"] < proof.BOUND_S * 1000
    assert set(report["tier_c_decisions"]) == {"executed"}, report["tier_c_decisions"]
    approvals = report["approved_tier_c_reply_to_act"]
    assert approvals["missed"] == 0 and approvals["max_ms"] < proof.BOUND_S * 1000
