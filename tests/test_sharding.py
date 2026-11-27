# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""`--ori-shard K/N` runs each test in exactly one of the N shards, and a
malformed shard is refused rather than running everything or nothing."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests import sharding

ROOT = Path(__file__).resolve().parents[1]
#: A module with enough tests that each of three shards gets some.
SAMPLE = "tests/test_ci_scopes.py"


def _collected(
    *args: str, workers: tuple[str, ...] = ("-p", "no:xdist")
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", *workers, *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _ids(run: subprocess.CompletedProcess[str]) -> set[str]:
    assert run.returncode == 0, run.stdout + run.stderr
    return {line for line in run.stdout.splitlines() if "::" in line}


@pytest.mark.parametrize("shards", [1, 2, 3, 5])
def test_every_node_falls_in_exactly_one_shard(shards: int) -> None:
    nodeids = [f"tests/test_m{i % 7}.py::test_{i}[case-{i}]" for i in range(2000)]
    seen = [sharding.shard_of(nodeid, shards) for nodeid in nodeids]
    assert set(seen) == set(range(1, shards + 1))
    # Even enough that no shard carries much more than its share.
    assert max(seen.count(k) for k in set(seen)) < 1.2 * len(nodeids) / shards


def test_the_shards_of_a_real_run_partition_its_collection() -> None:
    every = _ids(_collected(SAMPLE))
    parts = [_ids(_collected(SAMPLE, f"--ori-shard={k}/3")) for k in (1, 2, 3)]
    assert all(parts), "a shard of the sample collected nothing"
    assert sum(len(part) for part in parts) == len(every)
    assert set().union(*parts) == every


@pytest.mark.parametrize("spec", ["0/3", "4/3", "1/0", "3", "1/3/5", " 1/3", "a/b", ""])
def test_a_malformed_shard_is_refused(spec: str) -> None:
    run = _collected(SAMPLE, f"--ori-shard={spec}")
    assert run.returncode == pytest.ExitCode.USAGE_ERROR, run.stdout + run.stderr
    assert "--ori-shard takes K/N" in run.stderr


def test_a_malformed_shard_is_refused_under_workers() -> None:
    """CI runs under xdist, whose controller collects nothing itself."""
    run = _collected(SAMPLE, "--ori-shard=4/3", workers=("-n", "2"))
    assert run.returncode == pytest.ExitCode.USAGE_ERROR, run.stdout + run.stderr
    assert "--ori-shard takes K/N" in run.stdout + run.stderr
