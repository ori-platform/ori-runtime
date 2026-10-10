# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The load-proof workflow runs what it claims, and its report counts nothing short."""

from __future__ import annotations

import importlib.util
import shlex
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from types import ModuleType

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "load-proof.yml"
CI = ROOT / ".github" / "workflows" / "ci.yml"


def _report() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "load_proof_report", ROOT / "scripts" / "load_proof_report.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def _steps() -> dict[str, dict]:
    return {step["name"]: step for step in _workflow()["jobs"]["load-proof"]["steps"]}


def test_it_runs_only_by_hand_and_reads_only():
    workflow = _workflow()
    # PyYAML reads the bare key `on` as True.
    triggers = workflow.get("on", workflow.get(True))
    assert triggers is not None
    assert set(triggers) == {"workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read", "id-token": "none"}
    assert workflow["jobs"]["load-proof"]["timeout-minutes"] < 360


def test_the_burners_are_stopped_and_the_evidence_kept_whatever_happens():
    steps = _steps()
    for name in (
        "Stop the burners and the sampler",
        "Report what each run held",
        "Upload the evidence",
    ):
        assert steps[name].get("if") == "always()", name


def test_the_budgets_are_ci_s_own_step_and_it_exists():
    ci_steps = yaml.safe_load(CI.read_text())["jobs"]["test"]["steps"]
    (step,) = [s for s in ci_steps if s.get("name") == "Run the latency budgets alone"]
    argv = shlex.split(step["run"])
    assert argv[0] == "pytest"
    assert (
        "Run the latency budgets alone"
        in _steps()["Run the latency budgets alone, unloaded"]["run"]
    )


def test_nothing_skips_the_phone_tests_and_nothing_retries():
    text = WORKFLOW.read_text()
    assert "ORI_SKIP_PHONE_E2E" not in text
    assert "--reruns" not in text
    run = _steps()["Run the full suite under load"]["run"]
    assert "pytest tests/ " in run
    assert "timeout " in run


def test_every_scheduler_delay_target_exists():
    run = _steps()["Run the scheduler-delay regressions, unloaded"]["run"]
    targets = [
        t.strip('"') for t in shlex.split(run) if t.strip('"').startswith("tests/")
    ]
    assert targets
    for target in targets:
        path, _, node = target.partition("::")
        source = (ROOT / path).read_text()
        assert node.split("::")[0] in source, target


def test_the_unloaded_passes_run_before_any_burner_starts():
    names = list(_steps())
    burners = names.index("Start the burners and the load sampler")
    assert names.index("Run the latency budgets alone, unloaded") < burners
    assert names.index("Run the scheduler-delay regressions, unloaded") < burners
    assert names.index("Run the full suite under load") > burners


def _junit(path: Path, ids: list[str], failures: int = 0) -> None:
    suite = ET.Element(
        "testsuite",
        tests=str(len(ids)),
        failures=str(failures),
        errors="0",
        skipped="0",
    )
    for case_id in ids:
        classname, _, name = case_id.partition("::")
        ET.SubElement(suite, "testcase", classname=classname, name=name)
    root = ET.Element("testsuites")
    root.append(suite)
    ET.ElementTree(root).write(path)


def _proof(
    tmp_path: Path,
    *,
    runs: int = 2,
    load: float = 26.0,
    run_status: int = 0,
    different_ids: bool = False,
    budgets: bool = True,
    stall_failures: int = 0,
) -> Path:
    proof = tmp_path / "proof"
    proof.mkdir()
    (proof / "commit.txt").write_text("a" * 40 + " subject\n")
    (proof / "stress.txt").write_text("cores=4\npytest_workers=4\n")
    ids = ["tests.a::t1", "tests.b::t2"]
    if budgets:
        _junit(proof / "budgets.xml", ["tests.c::b1"])
    _junit(proof / "stall.xml", ["tests.d::s1"], failures=stall_failures)
    lines, samples = [], []
    for i in range(1, runs + 1):
        start = 1000 * i
        lines += [
            f"{start} start {i}",
            f"{start + 600} end {i} {run_status if i == runs else 0}",
        ]
        samples += [f"{start + t} {load:.2f} 0 0" for t in range(0, 601, 5)]
        _junit(
            proof / f"run-{i}.xml",
            ids + (["tests.e::extra"] if different_ids and i == runs else []),
        )
    (proof / "runs.txt").write_text("\n".join(lines) + "\n")
    (proof / "loadavg.txt").write_text("\n".join(samples) + "\n")
    return proof


def test_a_proof_that_held_its_load_and_passed_counts(tmp_path, capsys):
    proof = _proof(tmp_path)
    assert _report().main(["", str(proof), "5.0"]) == 0
    assert "**Counts.**" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("kwargs", "problem"),
    [
        ({"run_status": 1}, "did not pass"),
        ({"load": 12.0}, "held less than 5.0 load per core"),
        ({"different_ids": True}, "ran a different set of tests"),
        ({"budgets": False}, "Latency budgets, unloaded: no result"),
        ({"runs": 0}, "no loaded run started"),
        ({"stall_failures": 1}, "Scheduler delay, unloaded: failed or ran nothing"),
    ],
)
def test_a_proof_short_of_anything_does_not_count(tmp_path, capsys, kwargs, problem):
    proof = _proof(tmp_path, **kwargs)
    assert _report().main(["", str(proof), "5.0"]) == 1
    out = capsys.readouterr().out
    assert "**Does not count:**" in out
    assert problem in out


def test_an_unfinished_run_does_not_count(tmp_path, capsys):
    proof = _proof(tmp_path)
    runs = proof / "runs.txt"
    runs.write_text("\n".join(runs.read_text().splitlines()[:-1]) + "\n")
    assert _report().main(["", str(proof), "5.0"]) == 1
    assert "run 2 did not pass" in capsys.readouterr().out
