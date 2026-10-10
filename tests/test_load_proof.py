# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The load-proof workflow runs what it claims, and its report counts nothing short."""

from __future__ import annotations

import importlib.util
import shlex
import sys
import xml.etree.ElementTree as ET
from collections.abc import Sequence
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


def _junit(
    path: Path,
    passed: list[str],
    skipped: Sequence[str] = (),
    failed: Sequence[str] = (),
) -> None:
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite")
    for case_id, outcome in (
        [(c, None) for c in passed]
        + [(c, "skipped") for c in skipped]
        + [(c, "failure") for c in failed]
    ):
        classname, _, name = case_id.partition("::")
        case = ET.SubElement(suite, "testcase", classname=classname, name=name)
        if outcome:
            ET.SubElement(case, outcome)
    ET.ElementTree(root).write(path)


PHONE = "tests.test_runtime_mobile_delivery_e2e::test_delivers"
HELD = (
    "tests.test_runtime_mobile_delivery_e2e::"
    "test_faults_land_at_their_polls_however_slowly_the_output_is_read"
)


def _proof(
    tmp_path: Path,
    *,
    runs: int = 5,
    finished: int | None = None,
    load: float = 26.0,
    tail_load: float | None = None,
    sample_every: int = 5,
    run_status: int = 0,
    phone_skipped_from: int | None = None,
    budgets: str = "passed",
    held_reader: bool = True,
    held_reader_module: str = "tests.test_runtime_mobile_delivery_e2e",
    phone_module: str = "tests.test_runtime_mobile_delivery_e2e",
    last_samples_s: int = 600,
) -> Path:
    proof = tmp_path / "proof"
    proof.mkdir()
    (proof / "commit.txt").write_text("a" * 40 + " subject\n")
    (proof / "stress.txt").write_text("cores=4\npytest_workers=4\n")
    if budgets == "passed":
        _junit(proof / "budgets.xml", ["tests.c::b1"])
    elif budgets == "skipped":
        _junit(proof / "budgets.xml", [], skipped=["tests.c::b1"])
    held = held_reader_module + "::" + HELD.split("::")[1]
    _junit(proof / "stall.xml", ["tests.d::s1"] + ([held] if held_reader else []))
    phone = phone_module + "::test_delivers"
    lines, samples = [], []
    for i in range(1, runs + 1):
        start = 10_000 * i
        lines.append(f"{start} start {i}")
        if finished is None or i <= finished:
            lines.append(f"{start + 600} end {i} {run_status if i == runs else 0}")
        for t in range(0, last_samples_s + 1, sample_every):
            value = tail_load if tail_load is not None and t > 480 else load
            samples.append(f"{start + t} {value:.2f} 0 0")
        skip_phone = phone_skipped_from is not None and i >= phone_skipped_from
        _junit(
            proof / f"run-{i}.xml",
            ["tests.a::t1"] + ([] if skip_phone else [phone]),
            skipped=[phone] if skip_phone else [],
        )
    (proof / "runs.txt").write_text("\n".join(lines) + "\n")
    (proof / "loadavg.txt").write_text("\n".join(samples) + "\n")
    return proof


def _judge(
    proof: Path, floor: str = "5.0", target: str = "6.5", runs: str = "5"
) -> int:
    return _report().main(["", str(proof), floor, target, runs])


def test_a_proof_that_held_its_load_and_passed_counts(tmp_path, capsys):
    assert _judge(_proof(tmp_path)) == 0
    out = capsys.readouterr().out
    assert "**Counts.**" in out
    assert "Target 6.5 load per core; floor 5.0" in out


@pytest.mark.parametrize(
    ("proof_kwargs", "judge_kwargs", "problem"),
    [
        ({"run_status": 1}, {}, "run 5 did not pass"),
        ({"load": 12.0}, {}, "held less than 5.0 load per core"),
        ({"runs": 1}, {"runs": "1"}, "1 runs asked for, fewer than 5"),
        ({"runs": 3}, {}, "3 of 5 runs finished"),
        ({"finished": 4}, {}, "4 of 5 runs finished"),
        ({"phone_skipped_from": 2}, {}, "run 2 did not run the phone delivery tests"),
        (
            {"phone_skipped_from": 2},
            {},
            "ran different tests, or to different outcomes",
        ),
        ({"budgets": "missing"}, {}, "Latency budgets, unloaded: no result"),
        (
            {"budgets": "skipped"},
            {},
            "Latency budgets, unloaded: failed or passed nothing",
        ),
        (
            {"held_reader": False},
            {},
            "Scheduler delay, unloaded: " + HELD,
        ),
        ({}, {"floor": "0"}, "floor 0.0 is outside 1.0..6.5"),
        ({}, {"floor": "7"}, "floor 7.0 is outside 1.0..6.5"),
        ({"sample_every": 120}, {}, "too few load samples"),
        ({"tail_load": 0.4}, {}, "held less than 5.0 load per core"),
        ({"runs": 0}, {}, "0 of 5 runs finished"),
        ({"last_samples_s": 480}, {}, "gap in its load samples over 30 s"),
        (
            {"held_reader_module": "tests.test_load_proof"},
            {},
            "Scheduler delay, unloaded: tests.test_runtime_mobile_delivery_e2e::",
        ),
        (
            {"phone_module": "tests.test_runtime_mobile_delivery_e2e_extra"},
            {},
            "did not run the phone delivery tests",
        ),
    ],
)
def test_a_proof_short_of_anything_does_not_count(
    tmp_path, capsys, proof_kwargs, judge_kwargs, problem
):
    assert _judge(_proof(tmp_path, **proof_kwargs), **judge_kwargs) == 1
    out = capsys.readouterr().out
    assert "**Does not count:**" in out
    assert problem in out


def test_the_judge_is_the_workflow_s_own_revision():
    steps = _steps()
    assert steps["Checkout the judge"]["with"]["ref"] == "${{ github.sha }}"
    report = steps["Report what each run held"]["run"]
    assert "${RUNNER_TEMP}/judge/load_proof_report.py" in report
    assert "scripts/load_proof_report.py" not in report


def test_inputs_refuse_fewer_than_five_runs_and_a_floor_off_its_range():
    run = _steps()["Validate inputs"]["run"]
    assert "^([5-9]|[1-9][0-9])$" in run
    assert "1.0 <= f <= t <= 20.0" in run
    assert "os.environ" in run


def test_one_failed_unloaded_pass_does_not_cost_the_loaded_runs():
    steps = _steps()
    for name in (
        "Start the burners and the load sampler",
        "Run the full suite under load",
    ):
        assert steps[name].get("if") == (
            "${{ !cancelled() && steps.validate.outcome == 'success' "
            "&& steps.confirm.outcome == 'success' }}"
        ), name
    for step in steps.values():
        for line in step.get("run", "").splitlines():
            if "python" in line:
                assert "${TARGET}" not in line and "$TARGET" not in line, line
                assert "${FLOOR}" not in line and "$FLOOR" not in line, line
    run = steps["Run the full suite under load"]["run"]
    assert "-n auto" not in run
    assert "upload" not in run
    assert "run_attempt" in steps["Upload the evidence"]["with"]["name"]
