# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The bench latency proof stays runnable, and passes on an unloaded host."""

from __future__ import annotations

from pathlib import Path

from scripts import pi_dispatch_latency_proof as proof


async def test_the_proof_runs_and_both_shipped_tier_d_triggers_fire(
    tmp_path: Path,
) -> None:
    report = await proof._prove(tmp_path, 3)
    assert report["pass"] is True, report
    assert report["shed"] > 0, "the inbound route was never saturated"
    for name in proof.CASES:
        assert report[name]["readings"] == 3
        assert report[name]["missed"] == 0
        assert report[name]["max_ms"] < proof.BOUND_S * 1000
